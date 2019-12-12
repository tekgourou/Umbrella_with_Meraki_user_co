# import necessary libraries / modules
import warnings
import time
import sys, requests
from meraki import meraki
from calendar import timegm

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

#Get Meraki info
def getorgid(p_apikey, p_orgname):
    # looks up org id for a specific org name
    r = requests.get('https://dashboard.meraki.com/api/v0/organizations',
                     headers={'X-Cisco-Meraki-API-Key': p_apikey, 'Content-Type': 'application/json'})

    if r.status_code != requests.codes.ok:
        return 'null'

    rjson = r.json()

    for record in rjson:
        if record['name'] == p_orgname:
            return record['id']
    return ('null')


def getshardurl(p_apikey, p_orgid):
    # Looks up shard URL for a specific org. Use this URL instead of 'dashboard.meraki.com'
    # when making API calls with API accounts that can access multiple orgs.
    # On failure returns 'null'

    r = requests.get('https://dashboard.meraki.com/api/v0/organizations/%s/snmp' % p_orgid,
                     headers={'X-Cisco-Meraki-API-Key': p_apikey, 'Content-Type': 'application/json'})

    if r.status_code != requests.codes.ok:
        return 'null'

    rjson = r.json()

    return (rjson['hostname'])


def getnwlist(p_apikey, p_shardurl, p_orgid):
    # returns a list of all networks in an organization
    # on failure returns a single record with 'null' name and id

    r = requests.get('https://%s/api/v0/organizations/%s/networks' % (p_shardurl, p_orgid),
                     headers={'X-Cisco-Meraki-API-Key': p_apikey, 'Content-Type': 'application/json'})

    returnvalue = []
    if r.status_code != requests.codes.ok:
        returnvalue.append({'name': 'null', 'id': 'null'})
        return (returnvalue)

    return (r.json())


def getdevicelist(p_apikey, p_shardurl, p_nwid):
    # returns a list of all devices in a network

    r = requests.get('https://%s/api/v0/networks/%s/devices' % (p_shardurl, p_nwid),
                     headers={'X-Cisco-Meraki-API-Key': p_apikey, 'Content-Type': 'application/json'})

    returnvalue = []
    if r.status_code != requests.codes.ok:
        returnvalue.append({'serial': 'null', 'model': 'null'})
        return (returnvalue)

    return (r.json())


def get_serial_num(arg_apikey, arg_orgname ):
    arg_filepath = 'null'

    # get organization id corresponding to org name provided by user
    orgid = getorgid(arg_apikey, arg_orgname)
    if orgid == 'null':
        printusertext('ERROR: Fetching organization failed')
        sys.exit(2)

    # get shard URL where Org is stored
    shardurl = getshardurl(arg_apikey, orgid)
    if shardurl == 'null':
        printusertext('ERROR: Fetching Meraki cloud shard URL failed')
        sys.exit(2)

    # get network list for fetched org id
    nwlist = getnwlist(arg_apikey, shardurl, orgid)

    if nwlist[0]['id'] == 'null':
        printusertext('ERROR: Fetching network list failed')
        sys.exit(2)

    # if user selected to print in file, set flag & open for writing
    filemode = False
    if arg_filepath != 'null':
        try:
            f = open(arg_filepath, 'w')
        except:
            printusertext('ERROR: Unable to open output file for writing')
            sys.exit(2)
        filemode = True

    devicelist = []
    devicelist_serial_num = []
    for nwrecord in nwlist:
        # get devices' list
        devicelist = getdevicelist(arg_apikey, shardurl, nwrecord['id'])
        # append list to file or stdout

        for i in range(0, len(devicelist)):
                # MODIFY THE LINE BELOW TO CHANGE OUTPUT FORMAT
            devicelist_serial_num.append(devicelist[i]['serial'])

    return devicelist_serial_num

def get_username(apikey, serial_num, ip):
    clients = meraki.getclients(apikey, serial_num, suppressprint=True)
    try:
        for client in range(len(clients)):
            client_ip = clients[client]['ip']
            if ip == client_ip:
                try:
                    user = clients[client]['user']
                except:
                    user = None
                return user
    except:
        return

def get_users_from_meraki_net(ip):
    apikey = "PLEASE PROVIDE YOUR OWN MERAKI API KEY"
    org_name = 'YOUR ORG NAME'
    serials_num = get_serial_num(apikey, org_name)
    users = []
    for serial_num in serials_num:
        user = get_username(apikey, serial_num, ip)
        if user is not None:
            users.append(user)
    users = ','.join(users)
    return users

#Sending event to splunk
def send_splunk_event(msg):
    url = 'PLEASE PROVIDE YOUR OWN SPLUNK HTTP EVENT COLLECTOR'
    authHeader = {'Authorization': 'Splunk PLEASE PROVIDE YOUR OWN SPLUNK API KEY'}
    jsonDict = msg
    requests.post(url, headers=authHeader, json=jsonDict, verify=False)

#Get logs from Umbrella
def get_umbrella_security_events(last_timestamp):
    # API key and secret, combined, base64 encoded and decoded
    import base64
    API_key = "PLEASE PROVIDE YOUR OWN UMBRELLA REPORTING API KEY"
    API_secret = "PLEASE PROVIDE YOUR OWN UMBRELLA REPORTING SECRET KEY"
    API_combined = API_key + ":" + API_secret
    base64 = (base64.standard_b64encode(bytes(API_combined, 'utf-8'))).decode("utf-8")

    # enter organizational ID here
    organization = "PLEASE PROVIDE YOUR OWN UMBRELLA ORG NUM"

    # URL needed for the security activity
    reporting_url = "https://reports.api.umbrella.com/v1/organizations/" + organization + "/security-activity"

    #create header for authentication
    headers = {
        'Authorization': "Basic " + base64
        }
    querystring = {"limit": "500", "start": last_timestamp}
    print (querystring)
    # do GET request for the domain status and category
    req = requests.get(reporting_url, headers=headers, params=querystring)
    last_ip = ''
    print (req.json())
    if(req.status_code == 200):
        log = req.json()['requests']
        for event in log:
            originId = event['originId']
            originType = event['originType']
            originLabel = event['originLabel']
            externalip = event['externalIp']
            internalip = event['internalIp']
            categories = ', '.join(str(e) for e in event['categories'])
            destination = event['destination']
            tags = ', '.join(str(e) for e in event['tags'])
            action = event['actionTaken']
            timestamp = event['datetime']
            if internalip == None:
                src_ip = externalip
                meraki_users = 'Not Available'
            else:
                src_ip = internalip
                if src_ip != last_ip:
                    meraki_users = get_users_from_meraki_net(src_ip)
                    last_ip = src_ip

            if meraki_users == '':
                meraki_users = 'Not Available'
            event = "Umbrella Security Event : Meraki User : {}, categories: {}".format(meraki_users, categories)
            msg = {"event": event, "fields": {"originId": originId, "originType": originType, "originLabel": originLabel, "external_ip": externalip, "internal_ip": internalip, "meraki_user": meraki_users, "categories": categories, "destination": destination, "tags": tags, "action": action, "timestamp": timestamp}}
            #send_splunk_event(msg)
            print (msg)
            t_in_seconds = timegm(time.strptime(timestamp.replace('Z', 'GMT'), '%Y-%m-%dT%H:%M:%S.%f%Z'))
            last_timestamp = int(t_in_seconds)+1

    else:
        print("An error has ocurred with the following code %(error)s, please consult the following link: https://docs.umbrella.com/investigate-api/" % {'error': req.status_code})
    return last_timestamp

def main(last_timestamp):
    while True:
        last_timestamp = get_umbrella_security_events(last_timestamp)
        print('Last request: {}'.format(last_timestamp))
        time.sleep(15)

last_timestamp = int(time.time())
main(last_timestamp)
