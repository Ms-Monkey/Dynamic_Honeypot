import re

def main():
    fingerprint = ""
    nmap_class = ""
    TSeq = "TSEQ(Class=TR%IPID=I%TS=100HZ)\n"
    T1 = "\n"
    T2 = "\n"
    T3 = "\n"
    T4 = "\n"
    T5 = "\n"
    T6 = "\n"
    T7 = "\n"
    PU = "\n\n"
    all_vals = ""

    # This requires there is an empty line after each fingerprint
    regex_newline = "^\s*$"
    regex_T1 = "(T1).*R=([Y,N])%DF=([Y,N]).*F=(.{1,2})%.*"
    regex_T2 = "(T2).*R=([Y,N])%DF=([Y,N]).*W=(.{1,4})%.*F=(\w{1,2}).*"
    regex_T3 = ".*R=([Y,N])%DF=([Y,N]).*W=(.{1,4})%.*F=(\w{1,2}).*"
    regex_U1 = ".*DF=([Y,N]).*RID=(\w{1})%RIPCK=(\w{1}).*RUCK=(\w{1})"

    #open file
    file = open("/home/monkey/Desktop/whatever/input.txt", "r")
    writeout = open("/home/monkey/Desktop/whatever/output.txt", "w+")
    contents = file.readlines()

    for x in contents:
        # always add an \n to each val
        if x.startswith("Fingerprint"):
            fingerprint = x
            print(x)

        if x.startswith("T1"):
            test = re.match(regex_T1, x)
            # W=FFF0 is an Xp thing, 7 has =2000, as does 10
            # S++ is unknown
            # MNWNNT is unknown
            T1 = ("T1(DF=" + test.group(3) + "%W=FFF0%ACK=S++%Flags=" +
                test.group(4) + "%Ops=MNWNNT)\n")

        if x.startswith("T2"):
            test = re.match(regex_T2, x)
            # All hardcoded values unknown
            T2 = ("T2(Resp=" + test.group(2) + "%DF=" + test.group(3) +
                "%W=" + test.group(4) + "%ACK=S%Flags=" + test.group(5) + "%Ops=)\n")

        if x.startswith("T3"):
            test = re.match(regex_T3, x)
            # Disparity, Flags are AS in example and AR in nmap
            T3 = ("T3(Resp=" + test.group(1) + "%DF=" + test.group(2) +
                "%W=" + test.group(3) + "%ACK=S++%Flags=" + test.group(4)
                + "%Ops=MNWNNT)\n")

        if x.startswith("T4"):
            test = re.match(regex_T3, x)
            T4 = ("T4(DF=" + test.group(2) + "%W=" + test.group(3) +
                "%ACK=O%Flags=" + test.group(4) + "%Ops=)\n")

        if x.startswith("T5"):
            test = re.match(regex_T3, x)
            T5 = ("T5(DF=" + test.group(2) + "%W=" + test.group(3) +
                "%ACK=S++%Flags=" + test.group(4) + "%Ops=)\n")

        if x.startswith("T6"):
            test = re.match(regex_T3, x)
            T6 = ("T6(DF=" + test.group(2) + "%W=" + test.group(3) +
                "%ACK=O%Flags=" + test.group(4) + "%Ops=)\n")

        if x.startswith("T7"):
            test = re.match(regex_T3, x)
            T7 = ("T7(DF=" + test.group(2) + "%W=" + test.group(3) +
                "%ACK=O%Flags=" + test.group(4) + "%Ops=)\n")

        if x.startswith("U1"):
            test = re.match(regex_U1, x)
            #PU = ("PU(DF=" + test.group(1) + "%TOS=0%IPLEN=38%RIPTL=148%RID=" +
            #    test.group(2) + "%RIPCK=" + test.group(3) + "%UCK=" +
            #    test.group(4) + "%ULEN=134%DAT=E)\n\n")
            PU = ("PU(DF=" + test.group(1) + "%TOS=0%IPLEN=38%RIPTL=148%RID=E%RIPCK=E%UCK=E%ULEN=134%DAT=E)\n\n")

        if re.match(regex_newline, x):
            all_vals = (all_vals + fingerprint + nmap_class + TSeq +
                T1 + T2 + T3 + T4 + T5 + T6 + T7 + PU)

            print(all_vals)

    # When it hits an empty line writeout, then clear
    # the vals and start again
    writeout.write(all_vals)

if __name__ == "__main__":
    main()
