#!/usr/bin/env python3

VERSION="1.0g"

import sys,argparse,logging,os,humanize,itertools,math
from tabulate import tabulate
import datetime as dt
from astropy.io import fits
import dateutil.parser
from pathlib import Path
from functools import reduce
from string import Template
from astropy import units as u                                                                                                                                                                                                        
from astropy.coordinates import SkyCoord      

import xmltodict, traceback

from tqdm import tqdm
from functools import cmp_to_key

SCRIPT_DIR=Path(sys.argv[0]).parent
DEFAULT_CONFIG_FILE=SCRIPT_DIR.joinpath(Path(Path(sys.argv[0]).stem).with_suffix(".config.xml"))
PROJECT_INFO_FILE="astroReportProjectInfo.xml"
SCRIPT_NAME = Path(sys.argv[0]).stem

def doExit(err=0):
	if options.woe:
		input("Press Enter to exit")
	sys.exit(err)
	
def loadProjectInfo(f):
	if not os.path.exists(f):
		logger.critical("project info file not found: %s" % f)
		doExit(1)
		
	with open(f, "r") as ff:
		p=xmltodict.parse(ff.read(), force_list=('filter', 'object'))
	
	return p

def loadConfig(options):
	if not os.path.exists(options.config_file):
		logger.critical("config file not found: %s" % options.config_file)
		doExit(1)

	try:
		with open(options.config_file, "r") as f:
			p=xmltodict.parse(f.read())
			p["config"]["general"]["fitfile"]["@extensions"]
			p["config"]["general"]["filters"]["@naturalOrder"]
			if "astrobin" in p["config"].keys():
				p["config"]["astrobin"]["filtersID"]
				p["config"]["astrobin"]["equipment"]
				if set(p["config"]["astrobin"]["equipment"].keys()) != {'@focalRatio', '@darks', '@flats', '@bias'}:
					logger.critical("there is some missing info from astrobin config. Please review the config file")
					doExit(1)

			if "ekos" in p["config"].keys() and options.ekos:
				'''				
				if "equipment" not in p["config"].keys() or \
				not "camera" in p["config"]["equipment"].keys() or \
				set(p["config"]["equipment"]["camera"].keys()) != {'@width', '@height'}:
					logger.critical("equipment config missed or not completely defined. This is needed for ekos sequences creation. Please fix")
					sys.exit(1)
				'''					
				p["config"]["ekos"]["location"]
				p["config"]["ekos"]["sequences"]
				p["config"]["ekos"]["templates"]
				if  set(p["config"]["ekos"]["location"].keys()) != {'@name'}or \
				set(p["config"]["ekos"]["sequences"].keys()) != {'@dir'} or \
				set(p["config"]["ekos"]["templates"].keys()) != {'@subdir', '@sequenceJobTemplate','@sequenceTemplate','@scheduleJobTemplate','@scheduleTemplate'}:
					logger.critical("there is some missing info from ekos config. Please review the config file")
					doExit(1)
				ekosSequencesDir=p["config"]["ekos"]["sequences"]["@dir"]
				if not os.path.exists(ekosSequencesDir):
					logger.critical("ekos sequences dir %s does not exist. Please fix" % ekosSequencesDir)
					doExit(1)
				ekosTemplatesDir=SCRIPT_DIR.joinpath(p["config"]["ekos"]["templates"]["@subdir"])
				if not os.path.exists(ekosTemplatesDir):
					logger.critical("ekos templates dir %s does not exist. Please fix" % ekosTemplatesDir)
					doExit(1)
				for f in ['sequenceJobTemplate','sequenceTemplate','scheduleJobTemplate','scheduleTemplate']:
					if not os.path.exists(ekosTemplatesDir.joinpath(f)):
						logger.critical("some ekos template(s) do not exist. Please fix")
						doExit(1)

	except Exception as e:
		logger.critical("error while parsing config file. Find below the original exception; most likely due to a syntax error")
		traceback.print_exc()
		doExit(1)

	return p


def getFitHeaders(fit):
	def is_float(value):
	  if value is None:
		  return False
	  try:
		  float(value)
		  return True
	  except:
		  return False

	try:
		with fits.open(fit) as hduList:
			headers = ["READMODE", "OBJECT", "GAIN", "OFFSET",  "EXPTIME", "EXPOSURE", "IMAGETYP", "DATE-OBS", "CCD-TEMP", "FILTER", "XBINNING", "YBINNING","RA","DEC"]
			fitHeaders=dict(list(zip(headers, map(lambda x:hduList[0].header[x] if x.lower() in map(lambda x:x.lower(), hduList[0].header.keys()) else None ,headers))))
			for x in fitHeaders:
				fitHeaders[x]=float(fitHeaders[x]) if is_float(fitHeaders[x]) else fitHeaders[x].strip() if fitHeaders[x] is not None else fitHeaders[x]
	except:
		return None
	fitHeaders["EXPTIME"] = fitHeaders["EXPTIME"] if fitHeaders["EXPTIME"] is not None else fitHeaders["EXPOSURE"]
	fitHeaders["IMAGETYP"] = "LIGHT" if fitHeaders["IMAGETYP"] is not None and fitHeaders["IMAGETYP"].lower() in ["light frame", "light"] else fitHeaders["IMAGETYP"]
	try:
		fitHeaders["DATE-OBS"] = dateutil.parser.isoparse(fitHeaders["DATE-OBS"] )
	except:
		fitHeaders["DATE-OBS"] = None
	return fitHeaders

def is_valid_file(parser, arg):
	for fit in arg.split(","):
		if not os.path.exists(fit):
			parser.error("The file/dir %s does not exist!" % fit)
		else:
			return arg
        
def parse_options():
	usage = "%(prog)s"

	parser = argparse.ArgumentParser(usage=usage)
	parser.add_argument("-v", dest="verbose", action="store_true", help="write some debug info")
	parser.add_argument("-V", "--version", action="version", version=VERSION)
	parser.add_argument("--config-file", dest="config_file", default=DEFAULT_CONFIG_FILE, action="store", help="alternative xml config file. Default: %s" % DEFAULT_CONFIG_FILE)
	parser.add_argument("--ekos", dest="ekos", default=False, action="store_true", help="generate ekos sequences. Default: False")
	parser.add_argument("--wait-on-exit", "--woe", dest="woe", default=False, action="store_true", help="wait on exit. Default: False")
	parser.add_argument("dirs", nargs='+', type=lambda x: is_valid_file(parser, x))

	return parser

def setup_custom_logger(name, options):
    logger = logging.getLogger(name)

    formatter = logging.Formatter(fmt='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y/%m/%d %H:%M:%S')

    if options.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    handler = logging.StreamHandler(sys.stdout)

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger

def getObjectMainName(oobject, pinfo):
	# oobject = "M 81"
	# pinfo  = {'project': {'objects': {'object': [{'@name': 'M_81', '@aliases': 'M 81, bode', 'exposures': {'filter': [{'@name': 'L', '@subexposures': '180, 300', '@requiredTotalExposure': '10*3600', '@gain': '56', '@offset': '30'}, {'@name': 'R, G, B', '@subexposures': '180, 300', '@requiredTotalExposure': '3*3600', '@gain': '56', '@offset': '30'}]}, 'constraints': {'@minimumaltitude': '45'}}, {'@name': 'M_106', '@aliases': 'M 106, galaxyM106', 'exposures': {'filter': [{'@name': 'L', '@subexposures': '180, 300', '@requiredTotalExposure': '10*3600', '@gain': '56', '@offset': '30'}]}, 'constraints': {'@minimumaltitude': '45'}}]}}}
	if pinfo is not None:
		for ob in pinfo["project"]["objects"]["object"]:
			if ob["@name"].upper() == oobject.upper() or oobject.upper() in map(lambda x: x.upper(), map(lambda x: x.strip(), ob["@aliases"].split(","))): return ob["@name"]

	return None

def getObjectAliases(oobject, pinfo):
	if pinfo is not None:
		for ob in pinfo["project"]["objects"]["object"]:
			aliases = list(map(lambda x: x.strip(), ob["@aliases"].split(",")))
			if ob["@name"].upper() == oobject.upper(): return aliases

	return None

def getAllObjectsNames(pinfo, includeAlias=True):
	return reduce(lambda x,y: x+y, map(lambda x: [x["@name"]] + (list(map(lambda y: y.strip(), x["@aliases"].split(","))) if includeAlias else []) , pinfo["project"]["objects"]["object"])) 
		

def stringToList(s):
	# s = "M81, bode"
	return list(map(lambda x:x.strip(), s.split(",")))

def getObjectConfig(ob, pinfo):
	l=list(filter(lambda x: x["@name"] == ob, pinfo["project"]["objects"]["object"]))

	return l[0] if len(l) > 0 else None
	
def getObjectFilters(ob, pinfo):
	if pinfo is None: return []
	oc=getObjectConfig(ob, pinfo)
	# return [['L'], ['R', 'G', 'B']]
	return list(map(lambda x: stringToList(x), (map(lambda x:x["@name"], oc["exposures"]["filter"])))) if oc is not None else []

def getFilterProperties(oobject, filt, pinfo):
	# oobject = "M_81"
	# filt = 'L'
	# pinfo  = {'project': {'objects': {'object': [{'@name': 'M_81', '@aliases': 'M 81, bode', 'exposures': {'filter': [{'@name': 'L', '@subexposures': '180, 300', '@requiredTotalExposure': '10*3600', '@gain': '56', '@offset': '30'}, {'@name': 'R, G, B', '@subexposures': '180, 300', '@requiredTotalExposure': '3*3600', '@gain': '56', '@offset': '30'}]}, 'constraints': {'@minimumaltitude': '45'}}, {'@name': 'M_106', '@aliases': 'M 106, galaxyM106', 'exposures': {'filter': [{'@name': 'L', '@subexposures': '180, 300', '@requiredTotalExposure': '10*3600', '@gain': '56', '@offset': '30'}]}, 'constraints': {'@minimumaltitude': '45'}}]}}}
	for f in getObjectConfig(oobject, pinfo)["exposures"]["filter"]:
		if filt in stringToList(f["@name"]):
			return f

	return None

#####################################################################################



parser = parse_options()
options = parser.parse_args()

logger = setup_custom_logger('root', options)

logger.info("--- STARTING ---")
logger.info("running %s version %s" % (SCRIPT_NAME, VERSION))

config=loadConfig(options)

extensions=eval("list(%s)" % list(map(lambda x:x.strip(), config["config"]["general"]["fitfile"]["@extensions"].split(","))))
schedulerJobs=[]

for dir in options.dirs:
	logger.info("scanning files in %s" % dir)
	filesList = []
	for root, dirs, files in os.walk(dir, followlinks=True):
		for file in files:
			filesList.append(Path(root).joinpath(file))

	pinfo = None
	sessions={}
	objects={}
	bar=tqdm(range(len(filesList)))
	orphanedObjects=set()

	for fullPath in filesList:
		bar.update()

		if (Path(dir).joinpath(PROJECT_INFO_FILE)).exists() and pinfo is None:
			# get project info file only from the first level tree
			logger.debug("detected project info file: %s" % Path(dir).joinpath(PROJECT_INFO_FILE))
			pinfo = loadProjectInfo(Path(dir).joinpath(PROJECT_INFO_FILE))

#		if PROJECT_INFO_FILE == Path(fullPath).name and pinfo is None:
#			pinfo = loadProjectInfo(fullPath)
#
			# pinfo  = {'project': {'objects': {'object': [{'@name': 'M_81', '@aliases': 'M 81, bode', 'exposures': {'filter': [{'@name': 'L', '@subexposures': '180, 300', '@requiredTotalExposure': '10*3600', '@gain': '56', '@offset': '30'}, {'@name': 'R, G, B', '@subexposures': '180, 300', '@requiredTotalExposure': '3*3600', '@gain': '56', '@offset': '30'}]}, 'constraints': {'@minimumaltitude': '45'}}, {'@name': 'M_106', '@aliases': 'M 106, galaxyM106', 'exposures': {'filter': [{'@name': 'L', '@subexposures': '180, 300', '@requiredTotalExposure': '10*3600', '@gain': '56', '@offset': '30'}]}, 'constraints': {'@minimumaltitude': '45'}}]}}}

#			logger.debug("detected project info file: %s" % Path(root).joinpath(PROJECT_INFO_FILE))

		if True in map(lambda x:str(fullPath).endswith(x), extensions):
			# valid fit file
			logger.debug(fullPath)
			if not Path(fullPath).exists():
				logger.debug("skipping non existent (broken link?) file: %s" % fullPath)
				continue
			headers = getFitHeaders(fullPath)
			if headers is None:
				logger.warning("could not read headers from: %s  -- skipping" % fullPath)
				continue
			
			dateobs=headers["DATE-OBS"] if headers["DATE-OBS"] else None
			imagetyp=headers["IMAGETYP"]

			if dateobs is None: 
				logger.debug(" cannot determine observation date. Skipping")
				continue
			if imagetyp is None:
				logger.debug(" cannot determine image type. Skipping")
				continue
			if imagetyp != "LIGHT":
				logger.debug(" not a light frame. Skipping")
				continue
				
			gain=headers["GAIN"]
			offset=headers["OFFSET"]
			exptime=headers["EXPTIME"]
			ffilter=headers["FILTER"] if headers["FILTER"] is not None else ""
			ccd_temp=headers["CCD-TEMP"]
			oobject=headers["OBJECT"] if headers["OBJECT"] is not None else ""

			if oobject == "": logger.debug("file %s does not have an OBJECT fit header or is empty!" % fullPath)

			if pinfo is not None and oobject.upper() not in map(lambda x: x.upper(), getAllObjectsNames(pinfo)):
				logger.debug("skipping file %s with object not defined in project info (%s)" % (fullPath, oobject))
				orphanedObjects.add(oobject.upper())
				continue

			if pinfo is not None and oobject.upper() in map(lambda x: x.upper(), getAllObjectsNames(pinfo)):
				# figure out object's main name
				oobject=getObjectMainName(oobject, pinfo)

			midday = dateobs.replace(hour=12,minute=0,second=0,microsecond=0)
			sessiondate = midday if dateobs > midday else midday - dt.timedelta(days=1)
			
			if (pinfo is not None and ffilter in reduce(lambda x,y: x+y, getObjectFilters(oobject, pinfo))) or pinfo is None:
				# only compute if filter is defined in project or there is no project
				if sessiondate not in sessions.keys(): sessions[sessiondate] = []
				sessions[sessiondate].append({'file': fullPath, 'gain': gain, 'object': oobject, 'exptime': exptime, 'filter': ffilter, 'offset': offset, 'ccd_temp': ccd_temp})
				# sessions["20230314T1200"]=[{"file": "/home/...", "gain": "56", "object": "M_81", "exptime": "3600", "filter": "Ha", ... }, {"file":...}] 
			
				if oobject.upper() not in map(lambda x: x.upper(), objects.keys()): 
					objects[oobject] = {"exposures":{}}
				objects[oobject]["exposures"][ffilter] = exptime if ffilter.upper() not in map(lambda x: x.upper(), objects[oobject]["exposures"].keys()) else objects[oobject]["exposures"][ffilter]+exptime
				# objects={"M_81": {"exposures": {"L": 6400, "R": 3200}, "M_31": ... } }
	
	bar.close()
	
	logger.debug("found %s sessions" % len(sessions.keys()))
	if orphanedObjects != set(): logger.info("additional objects in %s: %s" % (dir, orphanedObjects))

	if pinfo is not None:
		# fill in 'objects' dict with possible missing info from project info (some object declared in config but not detected in the filesystem)
		# pinfo  = {'project': {'objects': {'object': [{'@name': 'M_81', '@aliases': 'M 81, bode', 'exposures': {'filter': [{'@name': 'L', '@subexposures': '180, 300', '@requiredTotalExposure': '10*3600', '@gain': '56', '@offset': '30'}, {'@name': 'R, G, B', '@subexposures': '180, 300', '@requiredTotalExposure': '3*3600', '@gain': '56', '@offset': '30'}]}, 'constraints': {'@minimumaltitude': '45'}}, {'@name': 'M_106', '@aliases': 'M 106, galaxyM106', 'exposures': {'filter': [{'@name': 'L', '@subexposures': '180, 300', '@requiredTotalExposure': '10*3600', '@gain': '56', '@offset': '30'}]}, 'constraints': {'@minimumaltitude': '45'}}]}}}		
		
		lostObjects = set(map(lambda x: x["@name"], pinfo["project"]["objects"]["object"])) - set(objects.keys())
		# lostObjects are the objects defined in the project but not detected in the dir
		if lostObjects != set():
			for lostObject in lostObjects:
				objects[lostObject] = {"exposures":{}}
				
		for oobject in pinfo["project"]["objects"]["object"]:
			# add missing filters (if any) from objects defined in project config
			objectConfig=getObjectConfig(oobject["@name"], pinfo)
			# objectConfig = {'@name': 'M_81', '@aliases': 'M 81, bode', 'exposures': {'filter': [{'@name': 'L', '@subexposures': '180, 300', '@requiredTotalExposure': '10*3600', '@gain': '56', '@offset': '30'}, {'@name': 'R, G, B', '@subexposures': '180, 300', '@requiredTotalExposure': '3*3600', '@gain': '56', '@offset': '30'}]}, 'constraints': {'@minimumaltitude': '45'}}
			for f in objectConfig["exposures"]["filter"]:
				for ff in stringToList(f["@name"]):
					if ff.upper() not in map(lambda x: x.upper(), objects[oobject["@name"]]["exposures"].keys()):
						objects[oobject["@name"]]["exposures"][ff] = 0
	
	print()
	print()
	if objects == {}:
		logger.info("no fits detected")
		continue
	else:
		for k, oobject in enumerate(objects.keys()):
			# oobject = "M_81"
			#print(objects[oobject])
			#allFilters=list(map(lambda x: stringToList(x), (map(lambda x:x["@name"], objectConfig["exposures"]["filter"])))) if objectConfig is not None else []
			#print(allFilters)
			#print(reduce(lambda x,y: x+y, allFilters))
			#print(list(objects[oobject]["exposures"].keys()))
			#sys.exit()
			logger.debug("dealing with object %s" % oobject)
			row=[]
			
			requiredTotalExposureAllFilters = 0
			remainingTimeAllFilters = 0
			
			def naturalOrderFilterSort(x, y):
				if not "filters" in config["config"]["general"].keys() or not "@naturalOrder" in config["config"]["general"]["filters"].keys(): return 0
				c=config["config"]["general"]["filters"]["@naturalOrder"]
				if x not in c and y in c:
					return 1
				if x in c and not y in c:
					return -1
				if x not in c and y not in c:
					return 0
				return -1 if c.index(x) < c.index(y) else 1

			iiter = reduce(lambda x,y: x+y, getObjectFilters(oobject, pinfo)) if pinfo is not None else objects[oobject]["exposures"].keys()
			iiter = sorted(iiter, key=cmp_to_key(naturalOrderFilterSort))
			for ffilter in iiter:
				# ffilter = "L"
				logger.debug("dealing with filter %s" % ffilter)
				if pinfo is None:
					logger.debug("no project info detected, so no subexposures count will be computed")
					row.append([ffilter if ffilter.strip() != "" else "[[ no filter ]]", humanize.precisedelta(objects[oobject]["exposures"][ffilter]), "--", "--", "--"])
					continue

				if getObjectMainName(oobject, pinfo) is None:
					# object doesn't exist in project info
					logger.debug("skipping non existent object '%s' in project info" % oobject)
					continue

				objectConfig=getObjectConfig(oobject, pinfo)
				objectConfig = objectConfig
				# objectConfig = {'@name': 'M_81', '@aliases': 'M 81, bode', 'exposures': {'filter': [{'@name': 'L', '@subexposures': '180, 300', '@requiredTotalExposure': '10*3600', '@gain': '56', '@offset': '30'}, {'@name': 'R, G, B', '@subexposures': '180, 300', '@requiredTotalExposure': '3*3600', '@gain': '56', '@offset': '30'}]}, 'constraints': {'@minimumaltitude': '45'}}
				# oobject = "M_81"
				# ffilter = 'L'
				allFilters=getObjectFilters(oobject, pinfo)
				# allFilters = [['L'], ['R', 'G', 'B']]
				allFiltersTF = list(map(lambda x: ffilter in x, allFilters))
				# allFiltersTF = [True, False]
				requiredTotalExposure = None
				collectedTime = objects[oobject]["exposures"][ffilter]
				remainingTime = None

				if True in allFiltersTF:
					# filter detected in project and object config
					filterInfo = objectConfig["exposures"]["filter"][allFiltersTF.index(True)]
					# filterInfo = {'@name': 'R, G, B', '@subexposures': '180, 300', '@requiredTotalExposure': '3*3600', '@gain': '56', '@offset': '30'}
					requiredTotalExposure = eval(filterInfo["@requiredTotalExposure"])
					requiredTotalExposureAllFilters += requiredTotalExposure
					remainingTime = requiredTotalExposure - collectedTime
					if remainingTime < 0: remainingTime = 0
					remainingTimeAllFilters += remainingTime
					for duration in stringToList(filterInfo["@subexposures"]):
						 subexposure={"count":math.ceil(remainingTime / float(duration)), "duration": duration, "filter": ffilter}
						 if subexposure["count"] > 0:
							 if "remainingSubexposures" not in objects[oobject].keys(): objects[oobject]["remainingSubexposures"] = []
							 objects[oobject]["remainingSubexposures"].append(subexposure)
				else:
					logger.debug("filter %s not defined in project for object %s" % (ffilter, objectConfig["@name"] if objectConfig is not None else "noObject"))
				if "remainingSubexposures" in objects[oobject].keys():
					r = objects[oobject]["remainingSubexposures"]
					remainingSubexposures = " || ".join(map(lambda x: str(x["count"])+" x "+str(x["duration"])+"sec" if x["count"] > 0 else "0", (filter(lambda x: x["filter"] == ffilter, r))))
				else:
					remainingSubexposures = None
				row.append([ffilter if ffilter.strip() != "" else "[[ no filter ]]", *list(map(lambda x: humanize.precisedelta(x), [collectedTime, requiredTotalExposure, remainingTime])), remainingSubexposures])
			
			if row != []: 
				print("Object summary")
				row.append([">>> TOTAL <<<" , humanize.precisedelta(reduce(lambda x,y: x+y, (map(lambda x: objects[oobject]["exposures"][x], objects[oobject]["exposures"].keys())))), humanize.precisedelta(requiredTotalExposureAllFilters), humanize.precisedelta(remainingTimeAllFilters)])
				#for fmt in ["plain","simple","github","grid","simple_grid","rounded_grid","heavy_grid","mixed_grid","double_grid","fancy_grid","outline","simple_outline","rounded_outline","heavy_outline","mixed_outline","double_outline","fancy_outline","pipe","orgtbl","asciidoc","jira","presto","pretty","psql","rst","mediawiki","moinmoin","youtrack","html","unsafehtml","latex","latex_raw","latex_booktabs","latex_longtable","textile","tsv"]:
					#print(fmt)
				print(tabulate(row, headers=[oobject if oobject.strip() != "" else "[[ no object ]]", "collected","required", "remaining time", "remaining subexposures"], tablefmt="pretty"))
				print()

			# sessions["20230314T1200"]=[{"file": "/home/...", "gain": "56", "object": "M_81", "exptime": "300", "filter": "Ha", ... }, {"file":...}] 
			# pinfo  = {'project': {'objects': {'object': [{'@name': 'M_81', '@aliases': 'M 81, bode', 'exposures': {'filter': [{'@name': 'L', '@subexposures': '180, 300', '@requiredTotalExposure': '10*3600', '@gain': '56', '@offset': '30'}, {'@name': 'R, G, B', '@subexposures': '180, 300', '@requiredTotalExposure': '3*3600', '@gain': '56', '@offset': '30'}]}, 'constraints': {'@minimumaltitude': '45'}}, {'@name': 'M_106', '@aliases': 'M 106, galaxyM106', 'exposures': {'filter': [{'@name': 'L', '@subexposures': '180, 300', '@requiredTotalExposure': '10*3600', '@gain': '56', '@offset': '30'}]}, 'constraints': {'@minimumaltitude': '45'}}]}}}
						
			if pinfo is not None or (pinfo is None and k == len(objects.keys())-1):
				# if no project info exists, print sessions only once
				if "astrobin" in config["config"].keys() and pinfo is not None: astrobincsv = [["date","filter","number","duration","gain","sensorCooling","fNumber","darks","flats","bias"]]
				sessionRows = []
				for i, s in enumerate(sorted(list(sessions.keys())), start=1):
					ffilters = {}
					for entry in sessions[s]:
						# entry = {'file': PosixPath('SESSION_06/M_81/Light/Ha/M_81_Light_Ha_300_secs__016.fits'), 'gain': 56.0, 'object': 'M_81', 'exptime': 300.0, 'filter': 'Ha', 'offset': 30.0, 'ccd_temp': -4.9}
						o1=getObjectMainName(entry["object"], pinfo)
						o1=o1 if o1 is not None else ""
						o2=getObjectMainName(oobject, pinfo)
						o2=o2 if o2 is not None else ""
						if pinfo is not None and o1.upper() != o2.upper(): continue
						if ((o1.upper() if pinfo is not None else entry['oobject'].upper()) == o2.upper()) if pinfo is not None else True:
							if entry["gain"] is not None:
								exptime=entry['exptime']
								ccd_temp=entry['ccd_temp'] 
								gain=int(entry['gain'])
								offset=int(entry['offset'])
								
								if entry["filter"] not in ffilters.keys(): 
									ffilters[entry["filter"]] = {"exposures":{}, "ccd_temp": 0}

								ffilters[entry["filter"]]["exposures"][exptime] = 1 if exptime not in ffilters[entry["filter"]]["exposures"].keys() else ffilters[entry["filter"]]["exposures"][exptime] + 1
								# I will take into account the min temperature registered
								ffilters[entry["filter"]]["ccd_temp"] = min([ccd_temp, ffilters[entry["filter"]]["ccd_temp"]])
								# hopefully gain will be always the same 8-)  If not, you have a problem!
								ffilters[entry["filter"]]["gain"] = gain
								ffilters[entry["filter"]]["offset"] = offset
							else:
								logger.warning("discarding file %s. No gain value within fits headers" % entry["file"])

					finfo=[]
					# ffilters = {'R': {'exposures': {120.0: 13}, 'ccd_temp': -5.0}, 'B': {'exposures': {120.0: 10}, 'ccd_temp': -5.0}, 'G': {'exposures': {120.0: 10}, 'ccd_temp': -5.0}}

					for ffilter in ffilters.keys():
						# ffilter="L"
						for exp in ffilters[ffilter]["exposures"].keys():
							finfo.append("%s: %s x %ssec" % (ffilter, ffilters[ffilter]["exposures"][exp], f'{exp:g}'))
							if "astrobin" in config["config"].keys() and pinfo is not None: 
								astrobincsv.append([str(s.date()), config["config"]["astrobin"]["filtersID"]["@"+ffilter] if "@"+ffilter in config["config"]["astrobin"]["filtersID"].keys() else "--", ffilters[ffilter]["exposures"][exp], ffilters[ffilter]["gain"], ffilters[ffilter]["ccd_temp"], config["config"]["astrobin"]["equipment"]["@focalRatio"], config["config"]["astrobin"]["equipment"]["@darks"], config["config"]["astrobin"]["equipment"]["@flats"], config["config"]["astrobin"]["equipment"]["@bias"]])

					if finfo!=[]: sessionRows.append(["SESSION_%s" % f"{i:02d}", ", ".join(finfo), s.date()])
					
					
				print("Sessions summary")
				print(tabulate(sessionRows, headers=["Session", "Lights","Date"], tablefmt="github") if sessionRows != [] else "no sessions data for object '%s'" % oobject)

				if "astrobin" in config["config"].keys() and pinfo is not None: 
					print()
					print("Astrobin csv summary:")
					for f in astrobincsv:
						print(','.join(map(lambda x:str(x), f)))

				print(); print()
		
			if "ekos" in config["config"].keys() and pinfo is not None and options.ekos:
				if "remainingSubexposures" in objects[oobject].keys():
					sequencesDir = Path(config["config"]["ekos"]["sequences"]["@dir"])
					logger.info("generating ekos files in %s" % sequencesDir)
					sequenceJobTemplate = Path(SCRIPT_DIR)
					sequenceJobTemplate = sequenceJobTemplate.joinpath(config["config"]["ekos"]["templates"]["@subdir"])
					sequenceJobTemplate = sequenceJobTemplate.joinpath(config["config"]["ekos"]["templates"]["@sequenceJobTemplate"])
					sequenceTemplate = Path(SCRIPT_DIR)
					sequenceTemplate = sequenceTemplate.joinpath(config["config"]["ekos"]["templates"]["@subdir"])
					sequenceTemplate = sequenceTemplate.joinpath(config["config"]["ekos"]["templates"]["@sequenceTemplate"])
					scheduleJobTemplate = Path(SCRIPT_DIR)
					scheduleJobTemplate = scheduleJobTemplate.joinpath(config["config"]["ekos"]["templates"]["@subdir"])
					scheduleJobTemplate = scheduleJobTemplate.joinpath(config["config"]["ekos"]["templates"]["@scheduleJobTemplate"])
					scheduleTemplate = Path(SCRIPT_DIR)
					scheduleTemplate = scheduleTemplate.joinpath(config["config"]["ekos"]["templates"]["@subdir"])
					scheduleTemplate = scheduleTemplate.joinpath(config["config"]["ekos"]["templates"]["@scheduleTemplate"])
					if not os.path.exists(sequenceJobTemplate) or not os.path.exists(sequenceTemplate):
						logger.critical("some ekos template is missing. Please review config. Skipping")
					else:
						# remainingSubexposures = [{'count': 164, 'duration': '180', 'filter': 'L'}, {'count': 47, 'duration': '120', 'filter': 'R'}, {'count': 50, 'duration': '120', 'filter': 'G'}, {'count': 50, 'duration': '120', 'filter': 'B'}]
						# logger.info("building sequences")
						sequenceJobs=[]
						filters=[]
						for remainingSubexposure in objects[oobject]["remainingSubexposures"]:
							# remainingSubexposure = {'count': 164, 'duration': '180', 'filter': 'L'}
							filters.append(remainingSubexposure["filter"])
							filterConfig=getFilterProperties(oobject,remainingSubexposure["filter"], pinfo)
							# filterConfig = {'@name': 'L', '@subexposures': '180', '@requiredTotalExposure': '10*3600', '@gain': '56', '@offset': '30', '@binning': '1'}
							d = {'filter':remainingSubexposure["filter"], 'exposure':remainingSubexposure["duration"], 'gain':filterConfig["@gain"],'count':remainingSubexposure["count"], 'offset':filterConfig["@offset"], "binX": filterConfig["@binning"], "binY": filterConfig["@binning"], "width": getObjectConfig(oobject, pinfo)["camera"]["@width"], "height": getObjectConfig(oobject, pinfo)["camera"]["@height"], "temperature": getObjectConfig(oobject, pinfo)["camera"]["@temperature"]}
							with open(sequenceJobTemplate) as f:
								src = Template(f.read())
								result = src.substitute(d)
								sequenceJobs.append(result)

						if sequenceJobs != []:
							d = {'jobs':"".join(sequenceJobs)}
							with open(sequenceTemplate, 'r') as f:
								src = Template(f.read())
								result = src.substitute(d)					

							fname = sequencesDir.joinpath(oobject+ "_"+"-".join(filters)+"_" + str(dt.date.today())+".esq")
							with open(fname,"w") as f:
								f.write(result)
								logger.info("sequence generated: %s" % fname)
								objectConfig = getObjectConfig(oobject, pinfo)
								ra, dec = 0, 0
								referenceFit = ""
								referenceFitFound = False
								if "referenceFit" in objectConfig.keys():
									if objectConfig["referenceFit"]["@file"] ==  "auto":
										logger.debug("trying to find a fit reference in %s for object %s" % (sequencesDir, oobject))
										for rroot, ddirs, ffiles in os.walk(sequencesDir, followlinks=True):
											if referenceFitFound: break
											for ffile in ffiles:
												if referenceFitFound: break
												ffx=Path(rroot).joinpath(ffile)
												if True in map(lambda x:str(ffx).endswith(x), extensions):
													# valid fit file
													logger.debug(" considering %s. Object is %s" % (ffx, getFitHeaders(ffx)["OBJECT"]))
													if getFitHeaders(ffx)["OBJECT"].lower() in  map(lambda x: x.lower(), getObjectAliases(oobject, pinfo) + [getObjectMainName(oobject, pinfo)]):
														logger.debug(" valid. Getting RA and DEC values")
														referenceFitFound=True
														try:
															coords = SkyCoord(ra=getFitHeaders(ffx)["RA"]*u.degree, dec=getFitHeaders(ffx)["DEC"]*u.degree, frame='icrs')       
															ra, dec = coords.ra.hour, coords.dec.deg
														except:
															logger.warning("could not retrieve AR and DEC coordinates from reference fit headers. Please fix manually in ekos scheduler when importing the .esl file")
														referenceFit=ffx
													else:
														logger.debug(" not valid")
									else:
										if not os.path.exists(objectConfig["referenceFit"]["@file"]):
											logger.warning("reference fit %s does not exist" % objectConfig["referenceFit"]["@file"])
								if not referenceFitFound:
									logger.warning("no fit reference for object %s. Getting RA and DEC from object name" % oobject)
									try:
										coords=SkyCoord.from_name(oobject)
										ra, dec = coords.ra.hour, coords.dec.deg
									except:
										logger.warning("could not retrieve AR and DEC coordinates from catalog. Please fix manually in ekos scheduler when importing the .esl file")
								
								d={"object": oobject, "ra": ra, "dec": dec, "sequence": fname, "fit": referenceFit, "constraints": ""}
								logger.debug("adding scheduler job: %s" % d)
								#schedulerJobs.append(sjob)
								with open(scheduleJobTemplate) as f:
									src = Template(f.read())
									result = src.substitute(d)
									schedulerJobs.append(result)
				else:
					logger.info("no remaining subexposures. No ekos sequences will be generated")
						

if schedulerJobs != []:
	logger.info("creating schedule")
	d = {'jobs':"".join(schedulerJobs)}
	with open(scheduleTemplate, 'r') as f:
		src = Template(f.read())
		result = src.substitute(d)					

	fname = sequencesDir.joinpath(str(dt.date.today())+".esl")
	with open(fname,"w") as f:
		f.write(result)
		logger.info("schedule generated: %s" % fname)

doExit()
