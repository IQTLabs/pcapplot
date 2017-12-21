from cymruwhois import Client
from scapy.utils import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from subprocess import call

import ast
import copy
import os
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
    print "Reading pcap file " + pcap_file + "...",
    sys.stdout.flush()
    capture = rdpcap(pcap_file)
    print "done"
    print "Storing sessions...",
    sys.stdout.flush()
    sessions = capture.sessions()
    print "done"
    sys.stdout.flush()
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

    i = 0
    ip_dports = {}
    num_sessions = float(len(sessions))
    for session in sessions:
        i += 1
        rows,columns = os.popen('stty size', 'r').read().split()
        rows = int(rows)
        columns = int(columns)

        sys.stdout.write('\r')
        sys.stdout.write(' ' * columns)
        sys.stdout.write('\r')
        sys.stdout.write('{}% done'.format((i / num_sessions) * 100))
        sys.stdout.flush()

        payload_len = 0
        s_num = 0
        s_type = "UNKNOWN"
        if sessions[session]:
            if sessions[session][TCP]:
                s_type = "TCP"
                s_num += 1
                p_num = 0
                for pkt in sessions[session][TCP]:
                    p_num += 1
                    try:
                        payload_len += len(pkt.payload)
                    except:
                        pass
            elif sessions[session][UDP]:
                s_type = "UDP"
                s_num += 1
                p_num = 0
                for pkt in sessions[session][UDP]:
                    p_num += 1
                    try:
                        payload_len += len(pkt.payload)
                    except:
                        pass
            if s_type != "UNKNOWN":
                try:
                    if (sessions[session][0][IP].src != '0.0.0.0' and
                        sessions[session][0][IP].src != '255.255.255.255' and
                        sessions[session][0][IP].dst != '0.0.0.0' and
                        sessions[session][0][IP].dst != '255.255.255.255'):
                        if sessions[session][0][IP].src not in aggr_dict:
                            aggr_dict[sessions[session][0][IP].src] = {}
                        if sessions[session][0][IP].dst not in aggr_dict[sessions[session][0][IP].src]:
                            aggr_dict[sessions[session][0][IP].src][sessions[session][0][IP].dst] = 0
                        aggr_dict[sessions[session][0][IP].src][sessions[session][0][IP].dst] = payload_len

                        # get ports
                        if sessions[session][0][IP].src not in ip_dports:
                            ip_dports[sessions[session][0][IP].src] = []
                        ip_dports[sessions[session][0][IP].src].append(sessions[session][0][IP].dport)
                except:
                    pass

                #print "src_ip: ", sessions[session][0][IP].src,
                #print ip_class(sessions[session][0][IP].src)
                #print "src_port: ", sessions[session][0][IP].sport
                #print "dst_ip: ", sessions[session][0][IP].dst,
                #print ip_class(sessions[session][0][IP].dst)
                #print "dst_port:", sessions[session][0][IP].dport
                #print "sessions: ", s_num
                #print "packets:", p_num
                #print "total payload length:", payload_len
                #print
    ROWS = 289
    COLUMNS = 289

    private_grid = []
    for row in range(ROWS):
        private_grid.append([])
        for column in range(COLUMNS):
            private_grid[row].append(0)

    private_map = populate_1918_space()

    ROWS = 256
    COLUMNS = 256
    asn_dict = {}
    c = Client()
    print
    for host in aggr_dict:
        if len(aggr_dict[host]) > 1:
            # get sent bytes
            print "host:", host
            with open('www/static/img/maps/manifest.txt', 'a+') as f:
                f.write(pcap_file.split("/")[-1] + ": " + host + "\n")
            for port in ip_dports[host]:
                dport_grid[port/ROWS][port%ROWS] = 1
            for peer in aggr_dict[host]:
                try:
                    r = c.lookup(peer)
                    if not r.asn:
                        if not r.cc:
                            # RFC 1918, etc.
                            #print "peer:", peer, "bytes out :", aggr_dict[host][peer]
                            priv_arr = private_map[".".join(peer.split(".")[:-1])]
                            private_grid[priv_arr[0]][priv_arr[1]] = 1
                        else:
                            print "found public IP without an ASN:", peer, "bytes out :", aggr_dict[host][peer]
                    else:
                        # public ip space
                        if r.asn in asn_dict:
                            asn_dict[r.asn]['bytes_out'] += aggr_dict[host][peer]
                        else:
                            asn_dict[r.asn] = {'owner': r.owner, 'bytes_out': aggr_dict[host][peer], 'bytes_in': 0}
                except Exception as e:
                    print peer, "FAILED TO LOOKUP ASN"
                    print sys.exc_info()[0], str(e)
        else:
            if host in ip_dports:
                for port in ip_dports[host]:
                    sport_grid[port/ROWS][port%ROWS] = 2
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
                        private_grid[priv_arr[0]][priv_arr[1]] = 2
                    else:
                        print "found public IP without an ASN:", host, "bytes out :", aggr_dict[host][dst]
                else:
                    # public ip space
                    if r.asn in asn_dict:
                        asn_dict[r.asn]['bytes_in'] += aggr_dict[host][dst]
                    else:
                        asn_dict[r.asn] = {'owner': r.owner, 'bytes_in': aggr_dict[host][dst], 'bytes_out': 0}
            except Exception as e:
                print host, "FAILED TO LOOKUP ASN"
                print sys.exc_info()[0], str(e)

    asn_grid = []
    for row in range(ROWS):
        asn_grid.append([])
        for column in range(COLUMNS):
            asn_grid[row].append(0)

    for asn in asn_dict:
        try:
            asn_num = int(asn)
            if asn_num < 65536:
                if asn_dict[asn]['bytes_out'] > asn_dict[asn]['bytes_in']:
                    asn_grid[asn_num/ROWS][asn_num%ROWS] = 1
                elif asn_dict[asn]['bytes_out'] < asn_dict[asn]['bytes_in']:
                    asn_grid[asn_num/ROWS][asn_num%ROWS] = 2
                else:
                    asn_grid[asn_num/ROWS][asn_num%ROWS] = 3
            else:
                print "ALERT!!!! high",
                print "external asn:", asn,
                print "asn owner:", asn_dict[asn]['owner'],
                print "total bytes sent:", asn_dict[asn]['bytes_out'],
                print "total bytes received:", asn_dict[asn]['bytes_in']
        except:
           pass
    return asn_grid, private_grid, sport_grid, dport_grid

def build_html():
    list_obj = """
  <li class="ui-state-default">
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
    legend = """%s<br />Host: %s<br /><br />Left to right:<br /><br />&emsp;&bull;&nbsp;Public ASN<br />&emsp;&bull;&nbsp;Private RFC 1918<br />&emsp;&bull;&nbsp;Source Ports<br />&emsp;&bull;&nbsp;Destination Ports"""
    image_paths = []
    for root, dirs, files in os.walk('www/static/img/maps'):
        for file in files:
            if file.endswith(".jpg"):
                image_paths.append(os.path.join(root, file))
    devices = {}
    for image in image_paths:
        try:
            if "-".join(image.split('-')[1:-3]) not in devices:
                devices["-".join(image.split('-')[1:-3])] = []
            devices["-".join(image.split('-')[1:-3])].append("-".join(image.split('.')[0].split('-')[-3:]))
        except Exception as e:
            print str(e)
            print "unexpected filename format, ignoring"

    # sort images per device
    dev_copy = copy.deepcopy(devices)
    for device in dev_copy:
        devices[device] = sorted(dev_copy[device])

    shutil.copy('www/index.html.orig', 'www/index.html')
    html_str = ""

    for device in devices:
        capture = device+'-'+devices[device][-1]+'.pcap'
        host = ''
        with open('www/static/img/maps/manifest.txt', 'r') as f:
            for line in f:
                if line.startswith(capture):
                    host = line.split(": ")[1].strip()
        tmp_legend = legend % (device, host)
        prefix = 'static/img/maps/'
        asn_path = 'map_ASN-'+device+'-'+devices[device][-1]+'.pcap.jpg'
        private_path = 'map_Private_RFC_1918-'+device+'-'+devices[device][-1]+'.pcap.jpg'
        src_path = 'map_Source_Ports-'+device+'-'+devices[device][-1]+'.pcap.jpg'
        dst_path = 'map_Destination_Ports-'+device+'-'+devices[device][-1]+'.pcap.jpg'

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
    return

def build_images(pcaps, processed_pcaps):
    for pcap_file in pcaps:
        try:
            asn_grid, private_grid, sport_grid, dport_grid = process_pcaps(pcap_file)
            draw(asn_grid, "ASN-"+pcap_file.split("/")[-1])
            draw(private_grid, "Private_RFC_1918-"+pcap_file.split("/")[-1], ROWS=289, COLUMNS=289, GRID_LINE=17)
            draw(sport_grid, "Source_Ports-"+pcap_file.split("/")[-1])
            draw(dport_grid, "Destination_Ports-"+pcap_file.split("/")[-1])
            processed_pcaps.append(pcap_file)
        except Exception as e:
            print str(e)
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            return processed_pcaps
    return processed_pcaps

def main():
    signal.signal(signal.SIGINT, signal_handler)
    pcaps = []
    processed_pcaps = []
    path = sys.argv[1]
    if path.endswith('.pcap'):
        pcaps.append(path)
    else:
        try:
            pcaps = ast.literal_eval(path)
        except:
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file.endswith(".pcap"):
                        pcaps.append(os.path.join(root, file))

    print "Found the following PCAP files:"
    for pcap_file in pcaps:
        print pcap_file
    print

    processed_pcaps = build_images(pcaps, processed_pcaps)
    os.system('reset')
    os.system('stty sane')
    pcaps = list(set(pcaps)-set(processed_pcaps))
    if pcaps:
        print "FAILURE, remaining pcaps: "
        print pcaps
        print
        print "Try again with the remaining PCAPs with this command:"
        print
        print 'python pcapplot.py "' + str(pcaps) + '"'
        print
        return

    build_html()
    print "Images are located in: 'www/static/img/maps'"

    try:
       call(["open", "www/index.html"])
       print "Opening a browser window to display results...",
    except:
       import SimpleHTTPServer
       import SocketServer

       PORT = 8000
       Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
       httpd = SocketServer.TCPServer(("", PORT), Handler)

       print "Open a browser window to display results, serving at http://0.0.0.0:" + str(PORT)+"/www/index.html"
       httpd.serve_forever()

    print "done"
    return

if __name__ == "__main__":
    main()
