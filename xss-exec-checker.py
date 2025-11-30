#!/usr/bin/env python

# XSS Exec Checker - Check and verify cross-site-scripting vulnerability of a specific endpoint - breve descrizione
# Copyright (C) 2025  Davide Quirillo
# Licensed under the GNU GPL v3 or later. See LICENSE for details.

import random, string
import argparse
import requests
from mimetypes import guess_file_type

PAYLOAD_DELIM_LEN = 7
html_special_chars =['<', '>', '"', "'"]

def rand_alphanum(n):
    s = ''.join(random.choices(string.ascii_letters + string.digits, k=n))
    return s

def send_request(payload: str):
    global args, request_bytes, request_headers, request_params

    if args.request_file:
        request_bytes = request_bytes.replace(b'XSS', payload.encode(), count=1)
        pass # send request_bytes() to the server using a tcp socket and receive resp
    else:
        m = args.method
        u = args.url
        # r=requests.post(u, headers=hs_dict)
        # return requests.post(TARGET, data={PARAM: payload}, timeout=10)

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
            for pf_line in f:
                payloads.append(pf_line.rstrip("\r\n"))
    manual_redirects = []
    if args.redirect:
        for r in args.redirect:
            man_redirects.append(r)

def static_check():
    global args
    global request_bytes, request_headers, request_params
    global payloads, manual_redirects

    print("Testing html special chars sanitization...")
    for c in html_special_chars:
        print("Character:", f'({c})')
        left_delim = rand_alphanum(PAYLOAD_DELIM_LEN)
        right_delim = rand_alphanum(PAYLOAD_DELIM_LEN)
        test_str = left_delim + c + right_delim
        send_request(test_str)
        print("Done")

def execution_check():
    pass

if __name__ == "__main__":
    get_args()
    init_args()
    static_check()
    execution_check()    
