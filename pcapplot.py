import http.server

from cymruwhois import Client
from datetime import datetime
from scapy.utils import PcapReader
from scapy.layers.inet import IP
from subprocess import call

import ast
import base64
import copy
import humanize
import json
import os
import pika
import shutil
import signal
import sys

from draw import draw

def signal_handler(signal, frame):
    os._exit(0)

def populate_1918_space():
    internal_map = {}
    inner = 0
    outer = 0

    # 10.x.x.x
    for oct1 in range(10,11):
        for oct2 in range(0,256):
            for oct3 in range(0,256):
                internal_map[str(oct1)+'.'+str(oct2)+'.'+str(oct3)] = [outer, inner]
                if inner == 289:
                    outer += 1
                    inner = 0
                else:
                    inner += 1
    # 172.16-31.x.x
    for oct1 in range(172,173):
        for oct2 in range(16,32):
            for oct3 in range(0,256):
                internal_map[str(oct1)+'.'+str(oct2)+'.'+str(oct3)] = [outer, inner]
                if inner == 289:
                    outer += 1
                    inner = 0
                else:
                    inner += 1

    # 192.168.x.x
    for oct1 in range(192,193):
        for oct2 in range(168,169):
            for oct3 in range(0,256):
                internal_map[str(oct1)+'.'+str(oct2)+'.'+str(oct3)] = [outer, inner]
                if inner == 289:
                    outer += 1
                    inner = 0
                else:
                    inner += 1

    return internal_map

def ip_class(ip):
    classes = ['public',          # 0
               '0.0.0.0/8',       # 1
               '10.0.0.0/8',      # 2
               '127.0.0.0/8',     # 3
               '169.254.0.0/16',  # 4
               '172.16.0.0/12',   # 5
               '192.0.0.0/24',    # 6
               '192.0.2.0/24',    # 7
               '192.18.0.0/15',   # 8
               '192.88.99.0/24',  # 9
               '192.168.0.0/16',  # 10
               '198.51.100.0/24', # 11
               '203.0.113.0/24',  # 12
               '224.0.0.0/4',     # 13
               '240.0.0.0/4'      # 14
              ]
    result = ''
    stripped_ip = ip.split(".")
    oct1 = stripped_ip[0]
    oct2 = stripped_ip[1]
    oct3 = stripped_ip[2]
    oct4 = stripped_ip[3]

    if int(oct1) == 0:
        result = classes[1]
    elif int(oct1) in range(1,10):
        result = classes[0]
    elif int(oct1) == 10:
        result = classes[2]
    elif int(oct1) in range(11,127):
        result = classes[0]
    elif int(oct1) == 127:
        result = classes[3]
    elif int(oct1) == 169 and int(oct2) == 254:
        result = classes[4]
    elif int(oct1) in range(128,172):
        result = classes[0]
    elif int(oct1) == 172 and int(oct2) in range(0,16):
        result = classes[0]
    elif int(oct1) == 172 and int(oct2) in range(16,32):
        result = classes[5]
    elif int(oct1) == 172 and int(oct2) in range(32,256):
        result = classes[0]
    elif int(oct1) in range(173,192):
        result = classes[0]
    elif int(oct1) == 192 and int(oct2) == 0 and int(oct3) == 0:
        result = classes[6]
    elif int(oct1) == 192 and int(oct2) == 0 and int(oct3) == 1:
        result = classes[0]
    elif int(oct1) == 192 and int(oct2) == 0 and int(oct3) == 2:
        result = classes[7]
    elif int(oct1) == 192 and int(oct2) == 0 and int(oct3) in range(3,256):
        result = classes[0]
    elif int(oct1) == 192 and int(oct2) in range(1,18):
        result = classes[0]
    elif int(oct1) == 192 and int(oct2) in range(18,20):
        result = classes[8]
    elif int(oct1) == 192 and int(oct2) in range(20,88):
        result = classes[0]
    elif int(oct1) == 192 and int(oct2) == 88 and int(oct3) in range(0,99):
        result = classes[0]
    elif int(oct1) == 192 and int(oct2) == 88 and int(oct3) == 99:
        result = classes[9]
    elif int(oct1) == 192 and int(oct2) == 88 and int(oct3) in range(100,256):
        result = classes[0]
    elif int(oct1) == 192 and int(oct2) in range(89,168):
        result = classes[0]
    elif int(oct1) == 192 and int(oct2) == 168:
        result = classes[10]
    elif int(oct1) == 192 and int(oct2) in range(169,256):
        result = classes[0]
    elif int(oct1) in range(193,198):
        result = classes[0]
    elif int(oct1) == 198 and int(oct2) in range(0,51):
        result = classes[0]
    elif int(oct1) == 198 and int(oct2) == 51 and int(oct3) in range(0,100):
        result = classes[0]
    elif int(oct1) == 198 and int(oct2) == 51 and int(oct3) == 100:
        result = classes[11]
    elif int(oct1) == 198 and int(oct2) == 51 and int(oct3) in range(101,256):
        result = classes[0]
    elif int(oct1) == 198 and int(oct2) in range(52,256):
        result = classes[0]
    elif int(oct1) in range(199,203):
        result = classes[0]
    elif int(oct1) == 203 and int(oct2) == 0 and int(oct3) in range(0,113):
        result = classes[0]
    elif int(oct1) == 203 and int(oct2) == 0 and int(oct3) == 113:
        result = classes[12]
    elif int(oct1) == 203 and int(oct2) == 0 and int(oct3) in range(114,256):
        result = classes[0]
    elif int(oct1) == 203 and int(oct2) in range(1,256):
        result = classes[0]
    elif int(oct1) in range(204,224):
        result = classes[0]
    elif int(oct1) in range(224,240):
        result = classes[13]
    elif int(oct1) in range(240,256):
        result = classes[14]
    # anything else is not a valid ipv4 address
    return result

def process_pcaps(pcap_file):
    aggr_dict = {}

    ROWS = 256
    COLUMNS = 256

    sport_grid = []
    for row in range(ROWS):
        sport_grid.append([])
        for column in range(COLUMNS):
            sport_grid[row].append(0)

    dport_grid = []
    for row in range(ROWS):
        dport_grid.append([])
        for column in range(COLUMNS):
            dport_grid[row].append(0)

    print("Reading pcap file " + pcap_file + "...")
    sys.stdout.flush()

    proto_dict = {17:'UDP', 6:'TCP'}
    ip_dports = {}
    packet_count = 0
    start_time = None
    end_time = None
    with PcapReader(pcap_file) as packets:
        for packet in packets:
            try:
                if (IP in packet) and (packet.proto in proto_dict.keys()):
                    if packet_count == 0:
                        start_time = packet.time
                    else:
                        end_time = packet.time
                    packet_count += 1
                    proto_name = proto_dict[packet.proto]
                    l3 = packet['IP']
                    l4 = packet[proto_name]
                    if (l3.src != '0.0.0.0' and l3.src != '255.255.255.255' and
                        l3.dst != '0.0.0.0' and l3.dst != '255.255.255.255'):
                        if l3.src not in aggr_dict:
                            aggr_dict[l3.src] = {}
                        if l3.dst not in aggr_dict[l3.src]:
                            aggr_dict[l3.src][l3.dst] = 0
                        aggr_dict[l3.src][l3.dst] += len(packet.payload)

                        # get ports
                        if l3.src not in ip_dports:
                            ip_dports[l3.src] = []
                        ip_dports[l3.src].append(l4.dport)
            except:
                # packet failed to parse, skipping
                pass

    print("done")

    ROWS = 289
    COLUMNS = 289

    private_grid = []
    for row in range(ROWS):
        private_grid.append([])
        for column in range(COLUMNS):
            private_grid[row].append([0, 0])

    private_map = populate_1918_space()

    ROWS = 256
    COLUMNS = 256
    asn_dict = {}
    c = Client()
    for host in aggr_dict:
        if len(aggr_dict[host]) > 1:
            # get sent bytes
            print("host: {0}".format(host))
            with open('www/static/img/maps/manifest.txt', 'a+') as f:
                f.write(pcap_file.split("/")[-1] + ": " + host + "\n")
            for port in ip_dports[host]:
                dport_grid[int(port/ROWS)][port%ROWS] = 1
            for peer in aggr_dict[host]:
                try:
                    r = c.lookup(peer)
                    if not r.asn:
                        if not r.cc:
                            # RFC 1918, etc.
                            #print "peer:", peer, "bytes out :", aggr_dict[host][peer]
                            priv_arr = private_map[".".join(peer.split(".")[:-1])]
                            private_grid[priv_arr[0]][priv_arr[1]][1] += aggr_dict[host][peer]
                        else:
                            print("found public IP without an ASN: {0} bytes out: {1}".format(peer, aggr_dict[host][peer]))
                    else:
                        # public ip space
                        if r.asn in asn_dict:
                            asn_dict[r.asn]['bytes_out'] += aggr_dict[host][peer]
                        else:
                            asn_dict[r.asn] = {'owner': r.owner, 'bytes_out': aggr_dict[host][peer], 'bytes_in': 0}
                except Exception as e:
                    print("{0} FAILED TO LOOKUP ASN".format(peer))
                    print(str(sys.exc_info()[0]) + str(e))
        else:
            if host in ip_dports:
                for port in ip_dports[host]:
                    sport_grid[int(port/ROWS)][port%ROWS] = 2
            # get received bytes
            dst = None
            # there is only one to loop through
            for d in aggr_dict[host]:
                dst = d
            try:
                r = c.lookup(host)
                if not r.asn:
                    if not r.cc:
                        # RFC 1918, etc.
                        #print "peer:", host, "bytes in:", aggr_dict[host][dst]
                        priv_arr = private_map[".".join(host.split(".")[:-1])]
                        private_grid[priv_arr[0]][priv_arr[1]][0] += aggr_dict[host][dst]
                    else:
                        print("found public IP without an ASN: {0} bytes out: {1}".format(host, aggr_dict[host][dst]))
                else:
                    # public ip space
                    if r.asn in asn_dict:
                        asn_dict[r.asn]['bytes_in'] += aggr_dict[host][dst]
                    else:
                        asn_dict[r.asn] = {'owner': r.owner, 'bytes_in': aggr_dict[host][dst], 'bytes_out': 0}
            except Exception as e:
                print("{0} FAILED TO LOOKUP ASN".format(host))
                print(str(sys.exc_info()[0]) + str(e))

    asn_grid = []
    for row in range(ROWS):
        asn_grid.append([])
        for column in range(COLUMNS):
            asn_grid[row].append([0, 0])

    for asn in asn_dict:
        try:
            asn_num = int(asn)
            if asn_num < 65536:
                asn_grid[int(asn_num/ROWS)][asn_num%ROWS] = [asn_dict[asn]['bytes_in'], asn_dict[asn]['bytes_out']]
            else:
                print("ALERT!!!! high external asn: {0} asn owner: {1} total bytes sent: {2} total bytes received: {3}".format(asn, asn_dict[asn]['owner'], asn_dict[asn]['bytes_out'], asn_dict[asn]['bytes_in']))
        except Exception as e:
            print(str(e))
    return asn_grid, private_grid, sport_grid, dport_grid, packet_count, humanize.naturaldelta(datetime.utcfromtimestamp(end_time) - datetime.utcfromtimestamp(start_time))

def build_html(pcap_stats):
    list_obj = """
  <li class="ui-state-default" style="background-color: #999999">
      <div id="wrapper">
      <div id="first"><p>%s</p></div>
      <div id="second">
      <a data-fancybox="gallery"
         data-srcset="%s"
         data-width="2561"
         data-height="2561"
         data-caption="&lt;b&gt;%s ASN&lt;/b&gt;&lt;br /&gt; Capture: %s"
         href="%s"><img src="%s" alt="" height="350" width="350">
      </a>
      <a data-fancybox="gallery"
         data-srcset="%s"
         data-width="2891"
         data-height="2891"
         data-caption="&lt;b&gt;%s Private RFC 1918&lt;/b&gt;&lt;br /&gt; Capture: %s"
         href="%s"><img src="%s" alt="" height="350" width="350">
      </a>
      <a data-fancybox="gallery"
         data-srcset="%s"
         data-width="2561"
         data-height="2561"
         data-caption="&lt;b&gt;%s Source Ports&lt;/b&gt;&lt;br /&gt; Capture: %s"
         href="%s"><img src="%s" alt="" height="350" width="350">
      </a>
      <a data-fancybox="gallery"
         data-srcset="%s"
         data-width="2561"
         data-height="2561"
         data-caption="&lt;b&gt;%s Destination Ports&lt;/b&gt;&lt;br /&gt; Capture: %s"
         href="%s"><img src="%s" alt="" height="350" width="350">
      </a>
      </div>
      </div>
  </li>
"""
    legend = """<b>%s</b><br /><b>Host:</b> %s<br /><b>Filename:</b> %s<br /><b>Packets:</b> %s<br /><b>Time window:</b> %s<br /><br /><b>Left to right:</b><br /><br />&emsp;&bull;&nbsp;Public ASN<br />&emsp;&bull;&nbsp;Private RFC 1918<br />&emsp;&bull;&nbsp;Source Ports<br />&emsp;&bull;&nbsp;Destination Ports"""
    image_paths = []
    for root, dirs, files in os.walk('www/static/img/maps'):
        for file in files:
            if file.endswith(".png"):
                image_paths.append(os.path.join(root, file))
    devices = {}
    for image in image_paths:
        try:
            if "-".join(image.split('-')[1:-3]) != '':
                if "-".join(image.split('-')[1:-3]) not in devices:
                    devices["-".join(image.split('-')[1:-3])] = []
                devices["-".join(image.split('-')[1:-3])].append("-".join(image.split('.')[0].split('-')[-3:]))
            else:
                print("unexpected filename format, ignoring")
        except Exception as e:
            print(str(e))
            print("unexpected filename format, ignoring")

    # sort images per device
    dev_copy = copy.deepcopy(devices)
    for device in dev_copy:
        devices[device] = sorted(list(set(dev_copy[device])))

    # create main page
    shutil.copy('www/index.html.orig', 'www/index.html')
    html_str = ""

    for device in devices:
        capture = device+'-'+devices[device][-1]+'.pcap'
        host = ''
        with open('www/static/img/maps/manifest.txt', 'r') as f:
            for line in f:
                if line.startswith(capture):
                    host = line.split(": ")[1].strip()
        tmp_legend = legend % ('<a href="'+device+'.html" style="color:blue">'+device+'</a>', host, capture, pcap_stats[capture][0], pcap_stats[capture][1])
        prefix = 'static/img/maps/'
        asn_path = 'map_ASN-'+device+'-'+devices[device][-1]+'.pcap.png'
        private_path = 'map_Private_RFC_1918-'+device+'-'+devices[device][-1]+'.pcap.png'
        src_path = 'map_Source_Ports-'+device+'-'+devices[device][-1]+'.pcap.png'
        dst_path = 'map_Destination_Ports-'+device+'-'+devices[device][-1]+'.pcap.png'

        html_str += list_obj % (tmp_legend, prefix+asn_path, device, capture,
                                prefix+asn_path, prefix+asn_path,
                                prefix+private_path, device, capture,
                                prefix+private_path, prefix+private_path,
                                prefix+src_path, device, capture,
                                prefix+src_path, prefix+src_path,
                                prefix+dst_path, device, capture,
                                prefix+dst_path, prefix+dst_path)
    with open('www/index.html', 'r') as f:
        filedata = f.read()
    filedata = filedata.replace("<!--fill in-->", html_str)
    with open('www/index.html', 'w') as f:
        f.write(filedata)

    # create device pages
    for device in devices:
        shutil.copy('www/index.html.orig', 'www/'+device+'.html')
        device_html_str = ""
        for cap in devices[device]:
            capture = device+'-'+cap+'.pcap'
            host = ''
            with open('www/static/img/maps/manifest.txt', 'r') as f:
                for line in f:
                    if line.startswith(capture):
                        host = line.split(": ")[1].strip()
            tmp_legend = legend % (device, host, capture, pcap_stats[capture][0], pcap_stats[capture][1])
            prefix = 'static/img/maps/'
            asn_path = 'map_ASN-'+device+'-'+cap+'.pcap.png'
            private_path = 'map_Private_RFC_1918-'+device+'-'+cap+'.pcap.png'
            src_path = 'map_Source_Ports-'+device+'-'+cap+'.pcap.png'
            dst_path = 'map_Destination_Ports-'+device+'-'+cap+'.pcap.png'

            device_html_str += list_obj % (tmp_legend, prefix+asn_path, device,
                                           capture, prefix+asn_path,
                                           prefix+asn_path, prefix+private_path,
                                           device, capture, prefix+private_path,
                                           prefix+private_path, prefix+src_path,
                                           device, capture, prefix+src_path,
                                           prefix+src_path, prefix+dst_path,
                                           device, capture, prefix+dst_path,
                                           prefix+dst_path)
        with open('www/'+device+'.html', 'r') as f:
            filedata = f.read()
        filedata = filedata.replace("<!--fill in-->", device_html_str)
        with open('www/'+device+'.html', 'w') as f:
            f.write(filedata)
    return

def build_images(pcaps, processed_pcaps, pcap_stats, rabbit=False, rabbit_host='messenger'):
    if rabbit:
        channel = connect_rabbit(host=rabbit_host)
    for pcap_file in pcaps:
        try:
            images = []
            asn_grid, private_grid, sport_grid, dport_grid, packet_count, time_delta = process_pcaps(pcap_file)
            images.append(draw(asn_grid, "ASN-"+pcap_file.split("/")[-1]))
            images.append(draw(private_grid, "Private_RFC_1918-"+pcap_file.split("/")[-1], ROWS=289, COLUMNS=289, GRID_LINE=17))
            images.append(draw(sport_grid, "Source_Ports-"+pcap_file.split("/")[-1]))
            images.append(draw(dport_grid, "Destination_Ports-"+pcap_file.split("/")[-1]))
            processed_pcaps.append(pcap_file)
            host = ''
            with open('www/static/img/maps/manifest.txt', 'r') as f:
                for line in f:
                    if line.startswith(pcap_file.split("/")[-1]):
                        host = line.split(": ")[1].strip()
            pcap_stats[pcap_file.split("/")[-1]] = (packet_count, str(time_delta), host)
            if rabbit:
                uid = os.getenv('id', 'None')
                file_path = os.getenv('file_path', 'None')
                for counter, image in enumerate(images):
                    with open(image, 'rb') as f:
                        encoded_string = base64.b64encode(f.read())
                    body = {'id': uid, 'type': 'data', 'img_path': image, 'data': encoded_string.decode('utf-8'), 'file_path': file_path, 'pcap': os.path.split(pcap_file)[-1], 'results': {'counter': counter+1, 'total': len(images), 'tool': 'pcapplot', 'version': get_version()}}
                    send_rabbit_msg(body, channel)
                pcap_stats['pcap'] = os.path.split(pcap_file)[-1]
                body = {'id': uid, 'type': 'metadata', 'file_path': file_path, 'data': pcap_stats, 'results': {'tool': 'pcapplot', 'version': get_version()}}
                send_rabbit_msg(body, channel)
        except Exception as e:
            print(str(e))
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
            return processed_pcaps, pcap_stats
    if rabbit:
        uid = os.getenv('id', 'None')
        file_path = os.getenv('file_path', 'None')
        body = {'id': uid, 'type': 'metadata', 'file_path': file_path, 'data': '', 'results': {'tool': 'pcapplot', 'version': get_version()}}
        send_rabbit_msg(body, channel)
    return processed_pcaps, pcap_stats

def connect_rabbit(host='messenger', port=5672, queue='task_queue'):
    params = pika.ConnectionParameters(host=host, port=port)
    connection = pika.BlockingConnection(params)
    channel = connection.channel()
    channel.queue_declare(queue=queue, durable=True)
    return channel

def send_rabbit_msg(msg, channel, exchange='', routing_key='task_queue'):
    channel.basic_publish(exchange=exchange,
                          routing_key=routing_key,
                          body=json.dumps(msg),
                          properties=pika.BasicProperties(
                          delivery_mode=2,
                         ))
    print(" [X] %s UTC %r %r" % (str(datetime.utcnow()),
                                 str(msg['id']), str(msg['file_path'])))
    return

def get_version():
    version = ''
    with open('VERSION', 'r') as f:
        for line in f:
            version = line.strip()
    return version

def main():
    signal.signal(signal.SIGINT, signal_handler)
    pcaps = []
    processed_pcaps = []
    pcap_stats = {}
    path = sys.argv[1]
    if path.endswith('.pcap'):
        pcaps.append(path)
    else:
        print(path)
        try:
            pcaps = ast.literal_eval(path)
        except:
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file.endswith(".pcap") and 'miscellaneous' not in file:
                        pcaps.append(os.path.join(root, file))

    if pcaps:
        print("Found the following PCAP files:")
    for pcap_file in pcaps:
        print(pcap_file)

    if 'rabbit' in os.environ and os.environ['rabbit'] == 'true':
        processed_pcaps, pcap_stats = build_images(pcaps, processed_pcaps, pcap_stats, rabbit=True)
    else:
        processed_pcaps, pcap_stats = build_images(pcaps, processed_pcaps, pcap_stats)
    pcaps = list(set(pcaps)-set(processed_pcaps))
    if pcaps:
        print("FAILURE, remaining pcaps: ")
        print(pcaps)
        print("Try again with the remaining PCAPs with this command:")
        print('python pcapplot.py "' + str(pcaps) + '"')
        return

    print("Images are located in: 'www/static/img/maps'")

    build_html(pcap_stats)

    return

if __name__ == "__main__":
    main()
