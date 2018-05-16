import sys
import time
import requests
import optparse
import json
import urllib2
import hashlib
  
str_payload_v1           = u"/b2s/rest/v1/payloads"
str_globalTag_v2         = u"/b2s/rest/v2/globalTags"
str_globalTag_payload_v2 = u"/b2s/rest/v2/globalTag/{0}/payloads"
str_brute_payload_v2     = u"/b2s/rest/v2/payload/{0}"



def getRequest(url):
        headers = {
        'Accept': 'application/json',
        }

        return requests.get(url, headers=headers)



def getPayloadsV1(url):
        url=url+str_payload_v1
	res = getRequest(url)
        body = []
	if res.status_code == requests.codes.ok:
        	body = json.loads(res.content)
        return body

def getPayloadsByGTV2(url,gt):
        url=url+str_globalTag_payload_v2.format(gt)
        #print url
        res = getRequest(url)
        body = []
        if res.status_code == requests.codes.ok:
                body = json.loads(res.content)
        return body
	


def getGTs(url):
	url=url+str_globalTag_v2
	res = getRequest(url)
	body = []
        if res.status_code == requests.codes.ok:
                body = json.loads(res.content)
        return body

def getPayloadsV2(url):
        gts = getGTs(url)
        payloads = []
        spinner = spinning_cursor()
	for gt in gts:	
	        sys.stdout.write(spinner.next())
    		sys.stdout.flush()
        	payloads.extend( getPayloadsByGTV2(url,gt['globalTagId']))
                #print gt['name'], len(payloads)
    		sys.stdout.write('\b')

        body = payloads
        return body

def getPayloadsIDs(payloads):
	return [p['payloadId'] for p in payloads if 'payloadId' in p]



def file_exists(location):
    request = urllib2.Request(location)
    request.get_method = lambda : 'HEAD'
    try:
        response = urllib2.urlopen(request)
        return True
    except urllib2.HTTPError:
        return False

def get_remote_md5_sum(url, max_file_size=100*1024*1024):
    remote = urllib2.urlopen(url)
    hash = hashlib.md5()

    total_read = 0
    while True:
        data = remote.read(4096)
        total_read += 4096

        if not data or total_read > max_file_size:
            break

        hash.update(data)

    return hash.hexdigest()

def spinning_cursor():
    while True:
        for cursor in '|/-\\':
            yield cursor

def checkPayloadsfiles(payloads):
        #outF = open(file_name, "w")
	inc_payloads = []
	miss_files = []
	cor_payloads = []
	cor_files = []
        spinner = spinning_cursor()
	for p in payloads:
	        sys.stdout.write(spinner.next())
    		sys.stdout.flush()
		if not file_exists(p['baseUrl']+p['payloadUrl']):
  			#print >>outF, p['baseUrl']+p['payloadUrl']
			inc_payloads.append(p)
			miss_files.append(p['baseUrl']+p['payloadUrl'])
		else:
			if get_remote_md5_sum(p['baseUrl']+p['payloadUrl'],10*1024*1024*1024) != p['checksum']:
				cor_files.append(p['baseUrl']+p['payloadUrl'])
                        	cor_payloads.append(p)
				#print p['baseUrl']+p['payloadUrl'],p['checksum'], get_remote_md5_sum(p['baseUrl']+p['payloadUrl'])
			
    		sys.stdout.write('\b')
        #outF.close() 			
	return inc_payloads,miss_files,cor_payloads,cor_files 	


def getPayloadsByIDV2(url,pid):
        url=url+str_brute_payload_v2.format(pid)
        res = getRequest(url)
        body = {}
        if res.status_code == requests.codes.ok:
                body = json.loads(res.content)
        return body

def bruteForcePayloads(url):
	payloads=[]
        spinner = spinning_cursor()
	for pid in range (0,100000):
	        sys.stdout.write(spinner.next())
    		sys.stdout.flush()
                tmp=getPayloadsByIDV2(url,pid)
		if tmp:
			payloads.append(getPayloadsByIDV2(url,pid))
    		sys.stdout.write('\b')
	return payloads

def dumpPayloadsToFile(payloads,file_name):
	with open(file_name, 'w') as outfile:
		json.dump(payloads, outfile)



if __name__ == '__main__':
        opt = optparse.OptionParser()
        opt.add_option('--url', '-u', default=u'')
        opt.add_option('--mode', '-m', default='test')

        options, args = opt.parse_args()
       
        if options.url=='':
		print "Must provide URL"
		sys.exit()

	payloads_v1 = getPayloadsV1(options.url)
        print "Number of payloads V1: %d" % len(payloads_v1)
        dumpPayloadsToFile(payloads_v1,'payloads_v1.json')    

        inc_payloads,miss_files,cor_payloads, cor_files = checkPayloadsfiles(payloads_v1) 
        dumpPayloadsToFile(inc_payloads,'incompatible_payloads_v1.json')
        dumpPayloadsToFile(miss_files,'miss_files_v1.json')
        dumpPayloadsToFile(cor_payloads,'cor_payloads_v1.json')
        dumpPayloadsToFile(cor_files,'cor_files_v1.json')
        print "Number of missing files %d" % len(inc_payloads)
        print "Number of corrupted files %d" % len(cor_payloads)

#        brute_payloads = bruteForcePayloads(options.url)
#        print "Number of brute forced payloads %d" % len(brute_payloads)
#        dumpPayloadsToFile(brute_payloads,'brute_payloads_v2.json')    

#        unique_brute_payloads = dict((v['payloadId'],v) for v in brute_payloads).values()
#        print "Number of unique brute forced payloads %d" % len(unique_brute_payloads)
#        dumpPayloadsToFile(unique_brute_payloads,'unique_brute_payloads_v2.json')    

        payloads_v2 = getPayloadsV2(options.url)
        print "Number of payloads V2 (GT->Payloads): %d" % len(payloads_v2)

        unique_payloads_v2 = dict((v['payloadId'],v) for v in payloads_v2).values() 
	print "Number of unique payloads V2 (remove duplicates by Id): %d" % len(unique_payloads_v2)

        dumpPayloadsToFile(unique_payloads_v2,'payloads.json')    
      
        inc_payloads,miss_files,cor_payloads,cor_files = checkPayloadsfiles(unique_payloads_v2) 
        dumpPayloadsToFile(inc_payloads,'incompatible_payloads_v2.json')
        dumpPayloadsToFile(miss_files,'miss_files_v2.json')
        dumpPayloadsToFile(cor_payloads,'cor_payloads_v2.json')
        dumpPayloadsToFile(cor_files,'cor_files_v2.json')
        print "Number of missing files %d" % len(inc_payloads)
        print "Number of corrupted files %d" % len(cor_payloads)
