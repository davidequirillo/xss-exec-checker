#!/usr/bin/env python

# XSS Exec Checker - check and verify cross-site-scripting vulnerability of a specific endpoint - breve descrizione
# Copyright (C) 2025  Davide Quirillo
# Licensed under the GNU GPL v3 or later. See LICENSE for details.

import random, string
import re
import argparse
import socket
import requests
from mimetypes import guess_file_type
from urllib.parse import urlparse

PAYLOAD_DELIM_LEN = 7
html_special_chars = ['<', '>', '"', "'"]
html_keywords = ['<script>']

def rand_alphanum(n):
    s = ''.join(random.choices(string.ascii_letters + string.digits, k=n))
    return s

def get_response(response):
    text = ""
    for k,v in response.headers.items():
        text += k + ": " + v + "\r\n"
    text += "\r\n" + response.text
    return text

def send_request(payload: str):
    global args, request_bytes, request_headers, request_params, manual_redirects
    t = 10
    responses = []

    if args.request_file:
        request_bytes = request_bytes.replace(b'XSS', payload.encode())
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        u = urlparse(args.url)
        u_arr = u.netloc.split(':')
        if len(u_arr) > 1:
            host = u_arr[0]
            port = u_arr[1]
        else:
            host = u_arr[0]
            port = "80"
        try:
            client_socket.connect((host, int(port)))
            client_socket.sendall(request_bytes)
            resp_bytes = b''
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                resp_bytes += data
            responses.append(resp_bytes.decode())
        except Exception as e:
            print('Failed raw request: '+ str(e))
        finally:
            client_socket.close()
        return responses
    else:
        try:
            m = args.method
            u = args.url
            u = u.replace(args.payload_mark, payload)
            pars = {}
            heads = {}
            for k, v in request_params.items():
                pars[k] = v.replace(args.payload_mark, payload)
            for k, v in request_headers.items():
                heads[k] = v.replace(args.payload_mark, payload)
            if (args.method == "post"):
                resp = requests.post(u, data=pars, headers=heads, timeout=t)
            elif (args.method == "delete"):
                resp = requests.delete(u, params=pars, headers=heads, timeout=t)
            elif (args.method == "put"):
                resp = requests.put(u, data=pars, headers=heads, timeout=t)
            else:
                resp = requests.get(u, params=pars, headers=heads, timeout=t)
        except Exception as e:
            print('Failed request: '+ str(e))
        
        print("Status:", resp.status_code)
        
        while (resp.status_code == 301) and (args.follow_redirects):
            u = resp.headers['Location']
            print("Follow redirect:", u)
            resp = requests.get(u, params=pars, headers=heads, timeout=t)
        responses.append(get_response(resp))
        for u in manual_redirects:
            print("Manual redirect:", u)
            resp = requests.get(u, params=pars, headers=heads, timeout=t)
            responses.append(get_response(resp))
        return responses

def get_args():
    global args

    parser = argparse.ArgumentParser(description="XSS Execution Checker: check/verify cross-site-scripting vulnerability of a specific endpoint")

    parser.add_argument(
        "-v", "--verbose", action="store_true", 
        help="print more output info"     
    )
    parser.add_argument(
        "-m", "--method", choices=['get', 'post', 'put', 'delete'], default="get", 
        help="http method"     
    )
    parser.add_argument(
        "-k", "--payload-mark", type=str, default="XSS", 
        help="payload mark string (default XSS)"
    )
    parser.add_argument(
        "-a", "--append-header", type=str, action="append", default=[], 
        help="append a http header row"
    )
    parser.add_argument(
        "-p", "--parameter", type=str, action="append", default=[], 
        help="add a request parameter (name=value)"     
    )
    parser.add_argument(
        "-u", "--upload-file", type=str, action="append", default=[], 
        help="append a file to upload (key=filepath)"     
    )
    parser.add_argument(
        "-t", "--request-file",
        help="request text file (header and body)"     
    )
    parser.add_argument(
        "-w", "--payloads", 
        help="file containing the list of XSS payloads to check (facultative)"
    )
    parser.add_argument(
        "-b", "--blind-xss", action="store_true", 
        help="blind mode"
    )
    parser.add_argument(
        "-f", "--follow-redirects", action="store_true", 
        help="follow eventual redirects"
    )
    parser.add_argument(
        "-r", "--redirect", type=str, action="append", default=[], 
        help="add a manual redirect"
    )
    parser.add_argument(
        "url", 
        help="URL (endpoint)"
    )

    args = parser.parse_args()
    if args.verbose:
        print("Verbose:", "yes")
    if args.request_file:
        print("Request file:", args.request_file)
    else:
        print("Method:", args.method)
        if args.append_header:
            for h in args.append_header:
                print("Header:", h)
        if args.parameter:
            for p in args.parameter:
                print("Param:", p)
        if args.upload_file:
            for f in args.upload_file:
                print("File:", f) 
    print("Payload mark:", args.payload_mark)
    if args.payloads:
        print("Payloads:", args.payloads)
    if args.blind_xss:
        print("Blind mode:", "yes")
    if args.follow_redirects:
        print("Follow redirects:", "yes")
    if args.redirect:
        for h in args.redirect:
            print("Header:", h)
    print("URL:", args.url)

def init_args():
    global args
    global request_bytes, request_headers, request_params
    global payloads, manual_redirects

    if args.request_file:
        with open(args.request_file, "rb") as rf:
            request_bytes = rf.read()
    else:
        hs_dict = {}   
        for h in args.append_header:
            h_arr = h.split(":")
            if (len(h_arr)==2):
                hs_dict[h_arr[0].strip()] = h_arr[1].strip()
        request_headers = hs_dict
        pm_dict = {}
        for p in args.parameter:
            p_arr = p.split("=")
            if (len(p_arr)==2):
                pm_dict[p_arr[0]] = p_arr[1]
        request_params = pm_dict
        files = []
        for f in args.upload_file:
            f_arr= f.split("=")
            if (len(f_arr)==2):
                fparam = f_arr[0]
                fpath = f_arr[1]
                (fmime, fenc) = guess_file_type(fpath)
                with open(fpath, "rb") as fd:
                    files.append((fparam, (fd.name, fd.read(), fmime)))
    payloads = []
    if args.payloads:
        with open(args.payloads, "r", encoding="utf-8") as pf:
            for pf_line in pf:
                payloads.append(pf_line.rstrip("\r\n"))
    manual_redirects = []
    if args.redirect:
        for r in args.redirect:
            manual_redirects.append(r)

def static_check():
    global args
    global request_bytes, request_headers, request_params
    global payloads, manual_redirects

    is_sufficient = True # static check is sufficient?

    print("Testing html special chars sanitization...")
    html_specials = html_special_chars + html_keywords
    for c in html_specials:
        print("Character:", f'({c})')
        left_delim = rand_alphanum(PAYLOAD_DELIM_LEN)
        right_delim = rand_alphanum(PAYLOAD_DELIM_LEN)
        test_str = left_delim + c + right_delim
        regex1 = rf'{left_delim}\&(.)+;{right_delim}'
        regex2 = '{0}(.)*{1}'.format(left_delim, right_delim)
        responses = send_request(test_str)
        for r in responses:
            if test_str in r:
                print("Vulnerable to XSS probably: ", test_str)
            elif re.search(regex1, r, re.IGNORECASE):
                print("Not vulnerable")
            elif re.search(regex2, r, re.IGNORECASE):
                print("The target does some filtering, trying dynamic checks...")
                is_sufficient = False
            else:
                print("Not vulnerable (try blind attack)")
        print("Done")
    return is_sufficient

def blind_attack():
    global args
    global request_bytes, request_headers, request_params
    global payloads
    
    for p in payloads:
        send_request(p) 

def execution_check():
    global args
    global request_bytes, request_headers, request_params
    global payloads

    # start/init playwright
    
    for p in payloads:
        responses = send_request(p)
        for resp in responses: 
            pass

if __name__ == "__main__":
    get_args()
    init_args()
    if args.blind_xss:
        blind_attack()
    else:
        run_test_is_needed = not static_check() 
        if (run_test_is_needed):
            execution_check() 
