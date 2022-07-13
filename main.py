import socket
import re
import json
import pandas as pd
import os
import time

# HOST = "whois.tcinet.ru"
FILE = "domains.xlsx"
PORT = 43

GOD_HOST = "whois.iana.org"

WHOIS = {
    "uz": "whois.uz",
    "ro": "www.nic.ro",
    "es": "nic.es",
}

err = ""


def get_whois(domain):
    if domain in WHOIS:
        return [WHOIS[domain]]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((GOD_HOST, PORT))
        s.sendall(str.encode(domain + "\r\n"))
        data = s.recv(16 * 1024).decode()
        return re.findall("whois: *(\S+)", data)


def get_data(url, whois):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(20)
        s.connect((whois, PORT))
        splt = url.split(".")
        if splt[-1] == "рф":
            res = []
            for part in splt:
                tmp = []
                tmp.append("xn-".encode(encoding="punycode"))
                tmp.append(part.encode(encoding="punycode"))
                res.append(b"".join(tmp))
            s.sendall(b".".join(res))
        else:
            s.sendall(url.encode())
        data = s.recv(32 * 1024).decode()
        return data


def try_get_data(url, whois):
    vars_ = [url, url + "\r\n", url + "\n"]

    for req in vars_:
        try:
            s = get_data(req, whois)
        except Exception as e:
            print("Get data error: ", e)
            continue
        if "timeout" in s.lower() or "timed out" in s.lower():
            print("Get data timeout: ", s)
            continue
        if s == "":
            print("Empty")
            continue
        if len(s) < 50:
            print(s)
            continue
        while len(s) < 170 and url.split(".")[-1] == "kg":
            try:
                s = get_data(req, whois)
            except Exception as e:
                print("Get data error: ", e)
                continue
        return s
    return


def nserver(arr):
    res = ("nserver", [])
    for i in arr:
        if i[0] == "nserver":
            res[1].append(i[1])
    return res


def parsing(url, pr):
    global err, WHOIS
    err = ""
    try:
        whois = get_whois(url.split(".")[-1])
        if not whois:
            whois = get_whois(url.split(".")[-1])
        whois = whois[0]
        WHOIS[url.split(".")[-1]] = whois
    except Exception as e:
        print("Get Whois error: ", e)
        err = "whois server не найден"
        return
    if pr:
        print("\nWhois server: ", whois)
        print("Domain: ", url, "\n")
    s = try_get_data(url, whois)
    if not os.path.exists(os.path.join("db")):
        os.mkdir(os.path.join("db"))
    if not os.path.exists(os.path.join("db", url.split(".")[-1])):
        os.mkdir(os.path.join("db", url.split(".")[-1]))
    if not s:
        return
    with open(os.path.join("db", url.split(".")[-1], "res.txt"), 'w') as f:
        try:
            f.write(s)
        except Exception as e:
            f.write("Error: " + str(e))
    if pr:
        print("Output of whois server:\n", s)
    print(json.dumps(s))
    ar = re.findall("[\t\n]*([^:\n%]+)[:n][\r\t\n ]+([^\n\r]+)[\r\n]+", s)
    # ar.append(nserver(ar))

    d = dict(ar)
    with open(os.path.join("db", url.split(".")[-1], "dict.json"), 'w') as f:
        json.dump(d, f, indent=2)
    if pr:
        print("\nDict:\n", json.dumps(d, indent=2), "\n")
    return ar


def test_parsing(url, pr):
    try:
        with open(os.path.join("db", url.split(".")[-1], "res.txt")) as f:
            s = f.read()
    except FileNotFoundError:
        return
    if pr:
        print("Output of whois server:\n", s)

    ar = re.findall("[\t\n]*([^:\n%]+)[:n][\r\t\n ]+([^\n\r]+)[\r\n]+", s)
    return ar


def one_format(s):
    s = s.split("-")
    if len(s) < 2:
        if "." in s[0]:
            s = s[0].split(".")
        elif " " in s[0]:
            s = s[0].replace("  ", " ")
            s = s.split(" ")
            s = [s[4], s[1], s[2]]
        else:
            return "a"
    if len(s[0]) != 4:
        s = list(reversed(s))
    if len(s) < 3:
        return "a"
    s = "".join([s[0][:4], s[1], s[2]])
    s = s.replace("Jan", "01")
    s = s.replace("Feb", "02")
    s = s.replace("Mar", "03")
    s = s.replace("Apr", "04")
    s = s.replace("May", "05")
    s = s.replace("Jun", "06")
    s = s.replace("Jul", "07")
    s = s.replace("Aug", "08")
    s = s.replace("Sep", "09")
    s = s.replace("Oct", "10")
    s = s.replace("Nov", "11")
    s = s.replace("Dec", "12")
    return s[:8]


def get_registar(d):
    registars = []
    orgs = []
    key_words = ["registrar", "registar", "registration service", "domain support"]
    del_words = ["privacy", "hidden"]
    for el in d:
        key = el[0]
        for word in key_words:
            if word in key.lower() and len(key) < 3*len(word):
                registars.append(el[1])
        if "organization" in key.lower():
            orgs.append(el[1])
    registars.sort()
    print(registars, orgs)
    if not registars:
        registars = orgs
    for i in range(len(registars) - 1, -1, -1):
        for word in del_words:
            if word in registars[i].lower() or registars[i].isdigit():
                del registars[i]
                break
    if registars:
        # while ("www." in registars[-1] or "whois" in registars[-1]) and len(registars) > 1:
        #     del registars[-1]
        return " \r\n".join(set(registars))
    return


def get_org(d):
    registars = []
    key_words = ["organization", "registrant", "org", "contact"]
    del_words = ["please", "privacy", "@", " data protected", "hidden"]
    for el in d:
        key = el[0]
        for word in key_words:
            if word in key.lower() and len(key) < 3*len(word):
                registars.append(el[1])
    registars.sort()
    print(registars)
    for i in range(len(registars) - 1, -1, -1):
        for word in del_words:
            if word in registars[i].lower() or registars[i].isdigit():
                del registars[i]
                break
    if registars:
        while ("www." in registars[-1] or "whois" in registars[-1]) and len(registars) > 1:
            del registars[-1]
        return " \r\n".join(set(registars))
    return


def get_date(d):
    dates = []
    key_words = ["date", "paid", "expire", "valid until", "time", "expiry"]
    for el in d:
        key = el[0]
        for word in key_words:
            if word in key.lower():
                date = one_format(el[1].strip())
                if not date[0].isnumeric():
                    continue
                dates.append(date)
                break
    dates.sort()
    print(dates)
    for i in range(len(dates) - 1, -1, -1):
        if dates[i] <= time.strftime("%Y%m%d"):
            del dates[i]
    if dates:
        correct_date = min(dates)
        return ".".join([correct_date[:4], correct_date[4:6], correct_date[6:]])
    return


def main(urls, pr=False):
    res = []
    for url in urls:
        d = parsing(url, pr)
        date, org, reg = None, None, None
        if d:
            date = get_date(d)
            reg = get_registar(d)
            org = get_org(d)
        if err:
            res.append([url, err, "", "", int(reg != None), int(org != None), int(date != None)])
        else:
            res.append([url, reg, org, date, int(reg != None), int(org != None), int(date != None)])
        # if input("Next?") == "b":
        #     return
    return res


def test_main(urls, pr=False):
    res = []
    for url in urls:
        d = test_parsing(url, pr)
        date, org, reg = None, None, None
        if d:
            date = get_date(d)
            reg = get_registar(d)
            org = get_org(d)
        if err:
            res.append([url, err, "", "", int(reg != None), int(org != None), int(date != None)])
        else:
            res.append([url, reg, org, date, int(reg != None), int(org != None), int(date != None)])
        # if input("Next?") == "b":
        #     return
    return res


def test(urls):
    ready = ["az", "asia", "biz", "com", "gr", "hk", "in", "info", "investment", "it", "net", "nl",
             "online", "org", "pl", "ru", "sk", "su", "tv", "tj", "uk", "рф"]

    not_ready_url = [i if i.split(".")[-1] not in ready else "" for i in urls]

    not_ready_url = urls

    check = ["ru", "рф", "com", "org", "uk", "hk", "eu", "de"]
    check = ["com"]
    check_urls = [i if i.split(".")[-1] in check else "" for i in not_ready_url]
    # check_urls = not_ready_url
    check_urls = set(check_urls)
    check_urls.remove("")
    print(check_urls)
    out = main(check_urls, True)

    df = pd.DataFrame(out)
    df.to_excel("Outfile_test.xlsx")


def prod(urls):
    out = main(urls, True)
    df = pd.DataFrame(out, columns=["url", "registrar", "organisation", "alert date", "registrar?", "org?", "date?"])
    try:
        df.to_excel("Outfile.xlsx")
    except Exception:
        input("Закрой файл!!!")
        df.to_excel("Outfile.xlsx")


def test_prod(urls):
    out = test_main(urls, True)
    df = pd.DataFrame(out, columns=["url", "registrar", "organisation", "alert date", "registrar?", "org?", "date?"])
    try:
        df.to_excel("Outfile_testprod.xlsx")
    except Exception:
        input("Закрой файл!!!")
        df.to_excel("Outfile_testprod.xlsx")


xl = pd.read_excel(FILE, header=None)[0]
urls = xl.values.tolist()
urls = sorted(list(set(urls)), key=lambda x: x.split(".")[-1])
tt = time.time()

# test(urls)
# test_prod(urls)
prod(urls)
print("Time: ", time.strftime("%M:%S", time.localtime(time.time() - tt)))
