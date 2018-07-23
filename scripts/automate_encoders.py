import sys
import subprocess
import argparse

#read the encoder list
x64_encoders = ['x64/xor','x64/zutto_dekiru']
x32_encoders = [
    'x86/add_sub',
    'x86/alpha_mixed',
    'x86/alpha_upper',
    'x86/avoid_underscore_tolower',
    'x86/avoid_utf8_tolower',
    'x86/bloxor',
    'x86/bmp_polyglot',
    'x86/call4_dword_xor',
    'x86/context_cpuid',
    'x86/context_stat',
    'x86/context_time',
    'x86/countdown',
    'x86/fnstenv_mov',
    'x86/jmp_call_additive',
    'x86/nonalpha',
    'x86/nonupper',
    'x86/opt_sub',
    'x86/service',
    'x86/shikata_ga_nai',
    'x86/single_static_bit',
    'x86/unicode_mixed',
    'x86/unicode_upper'
]


#windows and linux options
linux_options = {"CMD":"/bin/sh",
    "CPORT": "35540",
    "FILE": "/etc/shadow",
    "LHOST": "127.0.0.1",
    "LPORT": "4444",
    "LURI": "http://127.0.0.1/foo.bar",
    "MODE": "0666",
    "PASS": "metasploitpass",
    "PATH": "/etc/passwd",
    "RHOST": "8.8.8.8",
    "SCOPIED": "0",
    "SHELL": "/bin/sh",
    "USER": "metasploituser"
}

windows_options = {"AHOST": "127.0.0.1",
    "AUTOVNC": "true",
    "CMD": "dir",
    "DELETE":"true",
    "DLL":"/usr/share/metasploit-framework/data/vncdll.x86.dll",
    "DNSZONE": "adnszone.com",
    "EXE": "rund11.exe",
    "EXITFUNC": "process",
    "EXT": "exe",
    "HOPURL":"http://example.com/hop.php",
    "ICON":"NO",
    "INCLUDECMD":"false",
    "INCLUDEWSCRIPT":"false",
    "KHOST":"127.0.0.1",
    "LHOST":"127.0.0.1",
    "LPOST":"4444",
    "PASS":"metaspolitpass",
    "PEXEC":"/usr/share/metasploit-framework/data/vncdll.x86.dll",
    "PIPEHOST":"127.0.0.1",
    "PIPENAME":"msf-pipe",
    "TEXT":"hello world",
    "TITLE":"hello world",
    "URL":"https://localhost:443/evil.exe ",
    "USER":"metaploituser",
    "VNCHOST":"127.0.0.1",
    "VNCPORT":"5555",
    "WMIC":"false"
}


def checkoptions(payload, platform):
    command = ["msfvenom","-p",payload, "--list-options"]
    option_string = ""
    try:
        results = subprocess.check_output(command)
        output = results.decode('utf-8')
    except Exception as e:
        print(e)
        return option_string
    if platform == "linux":
        for option in linux_options:
            if option in output:
                option_string += "%s=%s " %(option,linux_options[option])
    else:
        for option in windows_options:
            if option in output:
                option_string += "%s=%s " % (option, windows_options[option])
    return option_string

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate MSF Payloads for Research')
    parser.add_argument("-f", "--file", help="file of payloads to read in")
    parser.add_argument("-a", "--arch", help="arch (x86 or x64)")
    parser.add_argument("-p", "--platform", help="platform (for options lookup)")
    args = parser.parse_args()

    with open(args.file,'r') as fp:
        contents = fp.readlines()
    payloads = [str(x).strip() for x in contents]
    for payload in payloads:
        print(payload)
        outputname = payload.replace("/","_")
        #lookup the options for the payload
        options = checkoptions(payload, args.platform)
        #gen once, and then go for the encoders
        try:
            command = ['msfvenom', '-p', payload, options, '-f', 'raw', '-o', outputname]
            output = subprocess.check_output(command)
        except Exception as e:
            continue
        #now go for the encoders
        if args.arch == 'x86':
            encoders = x32_encoders
        else:
            encoders = x64_encoders
        for encoder in encoders:
            outputname = "%s_%s" % (payload.replace("/","_"), encoder.replace("/","_"))
            try:
                command = ['msfvenom', '-p', payload, options, '-f', 'raw', '-e', encoder, '-o', outputname]
                output = subprocess.check_output(command)
            except Exception as e:
                print(output)
                continue
