#!/usr/bin/env python3

VERSION="1.0"

import sys,argparse,logging,os,humanize,itertools,math
from tabulate import tabulate
import datetime as dt
from astropy.io import fits
import dateutil.parser
from pathlib import Path
from functools import reduce

import xmltodict

from tqdm import tqdm

DEFAULT_CONFIG_FILE=Path(sys.argv[0]).parent.joinpath(Path(Path(sys.argv[0]).stem).with_suffix(".config.xml"))
PROJECT_INFO_FILE="astroReportProjectInfo.xml"
SCRIPT_NAME = Path(sys.argv[0]).stem

def loadProjectInfo(f):
	if not os.path.exists(f):
		logger.critical("project info file not found: %s" % f)
		sys.exit(1)
		
	with open(f, "r") as ff:
		p=xmltodict.parse(ff.read(), force_list=('filter', 'object'))
	
	return p


def loadConfig(options):
	if not os.path.exists(options.config_file):
		logger.critical("config file not found: %s" % options.config_file)
		sys.exit(1)
		
	with open(options.config_file, "r") as f:
		p=xmltodict.parse(f.read())
	
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
	
	with fits.open(fit) as hduList:
		headers = ["READMODE", "OBJECT", "GAIN", "OFFSET",  "EXPTIME", "EXPOSURE", "IMAGETYP", "DATE-OBS", "CCD-TEMP", "FILTER", "XBINNING", "YBINNING","RA","DEC"]
		fitHeaders=dict(list(zip(headers, map(lambda x:hduList[0].header[x] if x.lower() in map(lambda x:x.lower(), hduList[0].header.keys()) else None ,headers))))
		for x in fitHeaders:
			fitHeaders[x]=float(fitHeaders[x]) if is_float(fitHeaders[x]) else fitHeaders[x].strip() if fitHeaders[x] is not None else fitHeaders[x]
	
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
	








parser = parse_options()
options = parser.parse_args()

logger = setup_custom_logger('root', options)

logger.info("--- STARTING ---")
logger.info("running %s version %s" % (SCRIPT_NAME, VERSION))

config=loadConfig(options)

extensions=eval("list(%s)" % list(map(lambda x:x.strip(), config["config"]["general"]["fitfile"]["@extensions"].split(","))))
logger.info("generating report...")

for dir in options.dirs:
	filesList = []
	for root, dirs, files in os.walk(dir, followlinks=True):
		for file in files:
			filesList.append(Path(root).joinpath(file))

	pinfo = None
	sessions={}
	objects={}
	bar=tqdm(range(len(filesList)-1))
	orphanedObjects=set()

	for fullPath, b in zip(filesList, bar):
		if PROJECT_INFO_FILE == Path(fullPath).name and pinfo is None:
			pinfo = loadProjectInfo(fullPath)
			# pinfo  = {'project': {'objects': {'object': [{'@name': 'M_81', '@aliases': 'M 81, bode', 'exposures': {'filter': [{'@name': 'L', '@subexposures': '180, 300', '@requiredTotalExposure': '10*3600', '@gain': '56', '@offset': '30'}, {'@name': 'R, G, B', '@subexposures': '180, 300', '@requiredTotalExposure': '3*3600', '@gain': '56', '@offset': '30'}]}, 'constraints': {'@minimumaltitude': '45'}}, {'@name': 'M_106', '@aliases': 'M 106, galaxyM106', 'exposures': {'filter': [{'@name': 'L', '@subexposures': '180, 300', '@requiredTotalExposure': '10*3600', '@gain': '56', '@offset': '30'}]}, 'constraints': {'@minimumaltitude': '45'}}]}}}

			logger.debug("detected project info file: %s" % Path(root).joinpath(PROJECT_INFO_FILE))

		if True in map(lambda x:str(fullPath).endswith(x), extensions):
			# valid fit file
			logger.debug(fullPath)
			if not Path(fullPath).exists():
				logger.warning("skipping non existent (broken link?) file: %s" % fullPath)
				continue
			headers=getFitHeaders(fullPath)
			
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

			if oobject == "": logger.warning("file %s does not have an OBJECT fit header or is empty!" % fullPath)

			if pinfo is not None and oobject.upper() not in map(lambda x: x.upper(), getAllObjectsNames(pinfo)):
				logger.debug("skipping file %s with object not defined in project info (%s)" % (fullPath, oobject))
				orphanedObjects.add(oobject.upper())
				continue

			if pinfo is not None and oobject.upper() in map(lambda x: x.upper(), getAllObjectsNames(pinfo)):
				# figure out object's main name
				oobject=getObjectMainName(oobject, pinfo)

			midday = dateobs.replace(hour=12,minute=0,second=0,microsecond=0)
			sessiondate = midday if dateobs > midday else midday - dt.timedelta(days=1)
			
			if sessiondate not in sessions.keys(): sessions[sessiondate] = []
			sessions[sessiondate].append({'file': fullPath, 'gain': gain, 'object': oobject, 'exptime': exptime, 'filter': ffilter, 'offset': offset, 'ccd_temp': ccd_temp})
			# sessions["20230314T1200"]=[{"file": "/home/...", "gain": "56", "object": "M_81", "exptime": "3600", "filter": "Ha", ... }, {"file":...}] 

			if oobject.upper() not in map(lambda x: x.upper(), objects.keys()): objects[oobject] = {"exposures":{}}
			objects[oobject]["exposures"][ffilter] = exptime if ffilter.upper() not in map(lambda x: x.upper(), objects[oobject]["exposures"].keys()) else objects[oobject]["exposures"][ffilter]+exptime
			# objects={"M_81": {"exposures": {"L": 6400, "R": 3200}, "M_31": ... } }
	
	bar.close()
	
	logger.debug("found %s sessions" % len(sessions.keys()))
	if orphanedObjects != set(): logger.info("additional objects in %s: %s" % (dir, orphanedObjects))

	if pinfo is not None:
		# fill in 'objects' dict with possible missing info from project info (some object declared in config but not detected in the filesystem)
		# pinfo  = {'project': {'objects': {'object': [{'@name': 'M_81', '@aliases': 'M 81, bode', 'exposures': {'filter': [{'@name': 'L', '@subexposures': '180, 300', '@requiredTotalExposure': '10*3600', '@gain': '56', '@offset': '30'}, {'@name': 'R, G, B', '@subexposures': '180, 300', '@requiredTotalExposure': '3*3600', '@gain': '56', '@offset': '30'}]}, 'constraints': {'@minimumaltitude': '45'}}, {'@name': 'M_106', '@aliases': 'M 106, galaxyM106', 'exposures': {'filter': [{'@name': 'L', '@subexposures': '180, 300', '@requiredTotalExposure': '10*3600', '@gain': '56', '@offset': '30'}]}, 'constraints': {'@minimumaltitude': '45'}}]}}}		
		
		lostObjects = set(map(lambda x: x["@name"], pinfo["project"]["objects"]["object"])) - set(objects.keys())
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
	
	for k, oobject in enumerate(objects.keys()):
		# oobject = "M_81"
		logger.debug("dealing with object %s" % oobject)
		row=[]
		
		requiredTotalExposureAllFilters = 0
		remainingTimeAllFilters = 0
		for ffilter in objects[oobject]["exposures"].keys():
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
			allFilters=list(map(lambda x: stringToList(x), (map(lambda x:x["@name"], objectConfig["exposures"]["filter"])))) if objectConfig is not None else []
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
			print(tabulate(row, headers=[oobject if oobject.strip() != "" else "[[ no object ]]", "collected","required", "remaining time", "remaining subexposures"], tablefmt="simple_outline"))
			print()

		# sessions["20230314T1200"]=[{"file": "/home/...", "gain": "56", "object": "M_81", "exptime": "300", "filter": "Ha", ... }, {"file":...}] 
		# pinfo  = {'project': {'objects': {'object': [{'@name': 'M_81', '@aliases': 'M 81, bode', 'exposures': {'filter': [{'@name': 'L', '@subexposures': '180, 300', '@requiredTotalExposure': '10*3600', '@gain': '56', '@offset': '30'}, {'@name': 'R, G, B', '@subexposures': '180, 300', '@requiredTotalExposure': '3*3600', '@gain': '56', '@offset': '30'}]}, 'constraints': {'@minimumaltitude': '45'}}, {'@name': 'M_106', '@aliases': 'M 106, galaxyM106', 'exposures': {'filter': [{'@name': 'L', '@subexposures': '180, 300', '@requiredTotalExposure': '10*3600', '@gain': '56', '@offset': '30'}]}, 'constraints': {'@minimumaltitude': '45'}}]}}}
		
		
		if pinfo is not None or (pinfo is None and k == len(objects.keys())-1):
			# if no project info exists, print sessions only once
			sessionRows = []
			for i, s in enumerate(sorted(list(sessions.keys())), start=1):
				ffilters = {}
				for entry in sessions[s]:
					o1=getObjectMainName(entry["object"], pinfo)
					o1=o1 if o1 is not None else ""
					o2=getObjectMainName(oobject, pinfo)
					o2=o2 if o2 is not None else ""
					if pinfo is not None and o1.upper() != o2.upper(): continue
					if (o1.upper() if pinfo is not None else entry['oobject'].upper() == o2.upper()) if pinfo is not None else True:
						exptime=entry['exptime']
						if entry["filter"] not in ffilters.keys(): ffilters[entry["filter"]] = {}
						ffilters[entry["filter"]][exptime] = 1 if exptime not in ffilters[entry["filter"]].keys() else ffilters[entry["filter"]][exptime] + 1

				finfo=[]
				for ffilter in ffilters.keys():
					for exp in ffilters[ffilter].keys():
						finfo.append("%s: %s x %ssec" % (ffilter, ffilters[ffilter][exp], f'{exp:g}'))

				if finfo!=[]: sessionRows.append(["SESSION_%s" % f"{i:02d}", ", ".join(finfo), s.date()])

			print("Sessions summary")
			print(tabulate(sessionRows, headers=["Session", "Lights","Date"], tablefmt="github") if sessionRows != [] else "no sessions data for '%s'" % oobject)
			print(); print()
	
