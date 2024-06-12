from mitmproxy import http
from sniffdec.decrypter.aes_decrypter import AesDecrypter
import m3u8
from os import getcwd ,path, makedirs
from sniffdec.util import url, url_to_data_path, hex_str_to_iv
from sniffdec.netutil import check_port
from mitmproxy.tools.main import mitmdump
from uuid import uuid4
import random 
# global variables
hook = []

xref_uuid = {}

# track table, key is the uuid, value is the (key, iv, segment) path 
track_table = {} 

dump_path = path.join(getcwd(), 'sniffdec','dump', 'original')
decrypted_path = path.join(getcwd(), 'sniffdec', 'dump', 'decrypt')

def response(flow: http.HTTPFlow):
    global hook

    pure_url = flow.request.url.split('?')[0]
    if pure_url.endswith('.m3u8'):
        try:
            print("[🍕] m3u8 response detected: " + flow.request.url)
            content = flow.response.content.decode()
            data : m3u8.M3U8 = m3u8.loads(content, uri=flow.request.url)

            for seg, key in zip(data.segments, data.keys):
                uuid = uuid4().hex
                segment_url = url(seg.base_uri, seg.uri)
                key_url = None 
                iv = None
                method = None 

                xref_uuid[segment_url] = uuid
                hook.append(segment_url)
                
                if key:
                    key_url = url(key.base_uri, key.uri)
                    iv = hex_str_to_iv(key.iv)
                    method = key.method

                    xref_uuid[key_url] = uuid
                    hook.append(key_url) 

                track_table[uuid] = (key_url, iv, segment_url, method) 

        except Exception as e: 
            print("[🍉] failed to decode m3u8 data: " + str(e))

    # create directory for the file 
    if pure_url in hook:
        filepath = url_to_data_path(dump_path, pure_url)
        dirpath = path.dirname(filepath)
        makedirs(dirpath, exist_ok=True)
        with open(filepath, 'wb') as f:
            f.write(flow.response.content)

        uuid = xref_uuid[pure_url]
        key_url, iv, segment_url, method = track_table[uuid]
        if key_url != None and iv != None and path.exists(url_to_data_path(dump_path, key_url)) and path.exists(url_to_data_path(dump_path, segment_url)):
            print(f'[🍔] trying to decrypt {segment_url}...')
            encrypted = open(url_to_data_path(dump_path, segment_url), 'rb').read()
            key = open(url_to_data_path(dump_path, key_url), 'rb').read()
            
            target_path = url_to_data_path(decrypted_path, segment_url)
            makedirs(path.dirname(target_path), exist_ok=True)
            
            if method.lower().startswith('aes'):
                decrypter = AesDecrypter()
                decrypted = decrypter.decrypt(encrypted, key, iv)
                with open(target_path, 'wb') as f:
                    f.write(decrypted)
                print(f'[🍖] decrypted {segment_url} to {target_path}')
            else:
                print(f'[🍙] unsupported encryption method: {method}')
                

        
        


def main():
    print('[🧁] sniffdec is started')

    port = 8080 
    while not check_port(port):
        port = random.randint(1000, 50000)
    try: 
        print(f'[🍦] sniffdec is running on 0.0.0.0:{port}')
        print(f'[🍧] current working dir : {getcwd()}')
        mitmdump(['-q', '-s', __file__, '--listen-port', str(port)])
    except Exception as e:
        print("error with " + str(e))

if __name__ == "__main__":
    main()