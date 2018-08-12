import struct
import io


SECTOR_SIZE = 512

''' FAT Common Size and Seqence '''

JBC_SIZE = 3  # Jump Boot Code
OEM_NAME_SIZE = 8
BPS_SIZE = 2  # Bytes Per Sector
SPC_SIZE = 1  # Sector Per Cluster
RSC_SIZE = 2  # Reserved Sector Count
FAT_NUM_SIZE = 1
RDEC_SIZE = 2   # Root Dir Entry Count
TS16_SIZE = 2   # Total Sector 16
MEDIA_SIZE = 1
FAT16_SIZE = 2
SPT_SIZE = 2    # Sector Per Track
HEAD_NUM_SIZE = 2
HS_SIZE = 4 # Hidden Sector
TS32_SIZE = 4   # Total Sector 32

''' FAT Common Size and Seqence '''


''' FAT32 and Seqence '''

SIZE_OF_FAT32_SIZE = 4
EXT_FLAGS_SIZE = 2
FSV_SIZE = 2 # File System Version
RDC_SIZE = 4 # Root Directory Clustor
FSI_SIZE = 2 # File System Info
BRBS_SIZE = 2 # Boot Record Backup Sec
RESERVED_SIZE = 12
DRIVE_NUMBER_SIZE = 1
RESERVED1_SIZE = 1
BS_SIZE = 1 # Boot Signature
VID_SIZE = 4 # Volume ID
VL_SIZE = 11  # Volume Label
FST_SIZE = 8 # File System Type

''' FAT32 Size and Seqence '''

''' DIR Spec '''
DIR_SIZE = 32
NAME_SIZE = 8
EXT_SIZE = 3
ATTRIBUTE_SIZE = 1
NT_RESOURCE_SIZE = 1
CREATE_TIME_TENTH_SIZE = 1
CREATE_TIME_SIZE = 2
CREATE_DATE_SIZE = 2
LATE_ACCESS_DATE_SIZE = 2
FIRST_CLUSTER_HIGH_2_BYTE_SIZE = 2
WRITE_TIME_SIZE = 2
WRITE_DATE_SIZE = 2
FIRST_CLUSTER_LOW_2_BYTE_SIZE = 2
FILE_SIZE = 4   # if dir == 0
''' DIR Spec '''


def isascii(i):
    return (32 < i) & (i < 126)


def printByHex(bytes, size):
    fp = 0
    while fp < size:
        line = bytes[:16]
        bytes = bytes[16:]
        fp = fp + 16

        # print by hex
        for l in line:
            print("%02X" % l, end=' ')
            if hex(l).isalpha():
                print()

        # correct space
        if len(line) < 16:
            tmp = 16 - len(line)
            while tmp>0:
                print("  ", end=' ')
                tmp = tmp -1
        print(end='\t\t')

        # print ASCII
        for l in line:
            if isascii(l):
                print("%c" % l, end=' ')
            else:
                print('.', end=' ')
        print('')


def parseCommonFAT(drive):

    # parse FAT Common Table
    jbc = drive.read(JBC_SIZE)
    oem_name = drive.read(OEM_NAME_SIZE)
    bps = drive.read(BPS_SIZE)
    spc = drive.read(SPC_SIZE)
    rsc = drive.read(RSC_SIZE)
    fat_num = drive.read(FAT_NUM_SIZE)
    rdec = drive.read(RDEC_SIZE)
    ts16 = drive.read(TS16_SIZE)
    media = drive.read(MEDIA_SIZE)
    fat16_size = drive.read(FAT16_SIZE)
    spt = drive.read(SPT_SIZE)
    head_num = drive.read(HEAD_NUM_SIZE)
    hs = drive.read(HS_SIZE)
    ts32 = drive.read(TS32_SIZE)

    print("-----------------------------------------------------Common FAT-----------------------------------------------------")
    print("{:<30}".format("Jump Boot Code : "), end="")
    printByHex(jbc, JBC_SIZE)
    print("{:<30}".format("OEM Name : "), end="")
    printByHex(oem_name, OEM_NAME_SIZE)
    print("{:<30}".format("Bytes Per Sector  : "), end="")
    printByHex(bps, BPS_SIZE)
    print("{:<30}".format("Sector Per Cluster  : "), end="")
    printByHex(spc, SPC_SIZE)
    print("{:<30}".format("Reserved Sector Count  : "), end="")
    printByHex(rsc, RSC_SIZE)
    print("{:<30}".format("Number of FATs : "), end="")
    printByHex(fat_num, FAT_NUM_SIZE)
    print("{:<30}".format("Root Directory Entry Count : "), end="")
    printByHex(rdec, RDEC_SIZE)
    print("{:<30}".format("Total Sector 16 : "), end="")
    printByHex(ts16, TS16_SIZE)
    print("{:<30}".format("Media : "), end="")
    printByHex(media, MEDIA_SIZE)
    print("{:<30}".format("FAT Size 16 : "), end="")
    printByHex(fat16_size, FAT16_SIZE)
    print("{:<30}".format("Sector Per Track : "), end="")
    printByHex(spt, SPT_SIZE)
    print("{:<30}".format("Number of Heads : "), end="")
    printByHex(head_num, HEAD_NUM_SIZE)
    print("{:<30}".format("Hidden Sector : "), end="")
    printByHex(hs, HS_SIZE)
    print("{:<30}".format("Total Sector 32 : "), end="")
    printByHex(ts32, TS32_SIZE)
    print("-----------------------------------------------------Common FAT-----------------------------------------------------")

    return int.from_bytes(bps, byteorder='little'), int.from_bytes(spc, byteorder='little'), int.from_bytes(rsc, byteorder='little')


def parseFAT32(drive):

    # parse FAT32 table
    fat32_size = drive.read(SIZE_OF_FAT32_SIZE)
    ext_flags = drive.read(EXT_FLAGS_SIZE)
    fsv = drive.read(FSV_SIZE)
    rdc = drive.read(RDC_SIZE)
    fsi = drive.read(FSI_SIZE)
    brbs = drive.read(BRBS_SIZE)
    reserved = drive.read(RESERVED_SIZE)
    dn = drive.read(DRIVE_NUMBER_SIZE)
    reserved1 = drive.read(RESERVED1_SIZE)
    bs = drive.read(BS_SIZE)
    vid = drive.read(VID_SIZE)
    vl = drive.read(VL_SIZE)
    fst = drive.read(FST_SIZE)

    print("-------------------------------------------------------FAT32--------------------------------------------------------")
    print("{:<30}".format("FAT32 Size  (Sector): "), end="")
    printByHex(fat32_size, SIZE_OF_FAT32_SIZE )
    print("{:<30}".format("EXTs Flags : "), end="")
    printByHex(ext_flags, EXT_FLAGS_SIZE)
    print("{:<30}".format("File System Version : "), end="")
    printByHex(fsv, FSV_SIZE)
    print("{:<30}".format("Root Dir Cluster : "), end="")
    printByHex(rdc, RDC_SIZE)
    print("{:<30}".format("File System Info : "), end="")
    printByHex(fsi, FSI_SIZE)
    print("{:<30}".format("Boot Record Backup Sec : "), end="")
    printByHex(brbs, BRBS_SIZE)
    print("{:<30}".format("Reserved : "), end="")
    printByHex(reserved, RESERVED_SIZE)
    print("{:<30}".format("Drive Num : "), end="")
    printByHex(dn, DRIVE_NUMBER_SIZE)
    print("{:<30}".format("Reserved1 : "), end="")
    printByHex(reserved1, RESERVED1_SIZE)
    print("{:<30}".format("Boot Signature : "), end="")
    printByHex(bs, BS_SIZE)
    print("{:<30}".format("Volume ID : "), end="")
    printByHex(vid, VID_SIZE)
    print("{:<30}".format("Volume Label : "), end="")
    printByHex(vl, VL_SIZE)
    print("{:<30}".format("File System Type : "), end="")
    printByHex(fst, FST_SIZE)
    print("-------------------------------------------------------FAT32--------------------------------------------------------")

    return int.from_bytes(rdc, byteorder='little'), int.from_bytes(fat32_size, byteorder='little')


def parseRootDir(drive, fat32_table_addr, fat32_size ,root_dir_cluster):

    # must be add 1 every root_cluster Cuz cluster start at 0
    drive.seek(fat32_table_addr)
    table = drive.read(fat32_size)
    fat32_cluster_addr_size = 4 # FAT32 Cluster size is 4

    root_cluster = list()
    # parsing first root dir cluster
    root_addr = table[(root_dir_cluster) * fat32_cluster_addr_size: (root_dir_cluster * fat32_cluster_addr_size) + fat32_cluster_addr_size]

    while True:
        # add to list
        root_cluster.append(int.from_bytes(root_addr, byteorder='little'))

        # if there is no more cluster
        if int.from_bytes(root_addr, byteorder='little') == 0x0FFFFFFF:
            break

        # set next root addr for save to list and check next
        root_addr = table[((int.from_bytes(root_addr, byteorder='little') + 1) * fat32_cluster_addr_size):(root_dir_cluster*fat32_cluster_addr_size) + fat32_cluster_addr_size]

    return root_cluster


# def parseRootDir(reserved_sector, fat32_size, bytes_per_sector):
#
#     # cal root_dir_postion
#     reserved_section_size = reserved_sector * bytes_per_sector
#     fat_area_size = fat32_size * bytes_per_sector # for second FAT32(back up)
#     root_dir_postion = reserved_section_size + fat_area_size
#     print("------------------------------------------------------Root DIR------------------------------------------------------")
#     print("{:<30}{}".format("Reserved Section size : ", hex(reserved_section_size)))
#     print("{:<30}{}".format("FAT Area Size : ", hex(fat_area_size)))
#     print("{:<30}{}".format("Root Dir Postion : ", hex(root_dir_postion)))
#     print("------------------------------------------------------Root DIR------------------------------------------------------")
#
#     return root_dir_postion

def parseLFN(lfn_entry):

    order = lfn_entry[0:1]
    name1 = lfn_entry[1:11]
    attribute = lfn_entry[11:12]
    lfn_type = lfn_entry[12:13]
    checksum = lfn_entry[13:14]
    name2 = lfn_entry[14:26]
    fcl = lfn_entry[26:28]
    name3 = lfn_entry[28:32]
    name1.decode('utf-16') + name2.decode('utf-16') + name3.decode('utf-16')
    name_str = str()
    if int.from_bytes(order, byteorder='little') == 0xe5:
        return name1.decode('utf-16') + name2.decode('utf-16') + name3.decode('utf-16'), 0
    # if the last string
    if int.from_bytes(order, byteorder='little') > 0x40 :

        loop_count = (int.from_bytes(order, byteorder='little') - 0x40) - 1  # -1 is current entry
        while loop_count > 0:
            # parse next dir
            lfn_entry = lfn_entry[32:]
            name_str += parseLFN(lfn_entry)
            loop_count -= 1

        # add current name(the last name)
        name_str += name1.decode('utf-16') + name2.decode('utf-16') + name3.decode('utf-16')
        return name_str, (int.from_bytes(order,byteorder='little') - 0x40) # return name_str and total loopcount
    else:
        return name1.decode('utf-16') + name2.decode('utf-16') + name3.decode('utf-16')


def parseDir(dir_cluster) :
    print("------------------------------------------------------Root DIR------------------------------------------------------")
    while True:
        location = 0

        dir_name = dir_cluster[0:NAME_SIZE]
        location += NAME_SIZE
        if int.from_bytes(dir_name,byteorder='little')==0:
            break
        ext = dir_cluster[location: location + EXT_SIZE]
        location += EXT_SIZE

        attribute = dir_cluster[location: location + ATTRIBUTE_SIZE]
        location += ATTRIBUTE_SIZE

        nt_resource = dir_cluster[location: location + NT_RESOURCE_SIZE]
        location += NT_RESOURCE_SIZE

        ctt = dir_cluster[location: location + CREATE_TIME_TENTH_SIZE]
        location += CREATE_TIME_TENTH_SIZE

        ct = dir_cluster[location: location + CREATE_TIME_SIZE]
        location += CREATE_TIME_SIZE

        cd = dir_cluster[location: location + CREATE_DATE_SIZE]
        location += CREATE_DATE_SIZE

        lad = dir_cluster[location: location + LATE_ACCESS_DATE_SIZE]
        location += LATE_ACCESS_DATE_SIZE

        fch2 = dir_cluster[location: location + FIRST_CLUSTER_HIGH_2_BYTE_SIZE]
        location += FIRST_CLUSTER_HIGH_2_BYTE_SIZE

        wt = dir_cluster[location: location + WRITE_TIME_SIZE]
        location += WRITE_TIME_SIZE

        wd = dir_cluster[location: location + WRITE_DATE_SIZE]
        location += WRITE_DATE_SIZE

        fcl2 = dir_cluster[location: location + FIRST_CLUSTER_LOW_2_BYTE_SIZE]
        location += FIRST_CLUSTER_LOW_2_BYTE_SIZE

        fs = dir_cluster[location: location + FILE_SIZE]
        location += FILE_SIZE

        print('{:<30}'.format('Name : '), end='')
        if int.from_bytes(attribute, byteorder='little') == 0x08:
            name , loop_count = parseLFN(dir_cluster[location:])
            print(name)
            location = location + (loop_count * 32)
        elif int.from_bytes(attribute, byteorder='little') == 0x0F:
            name, loop_count = parseLFN(dir_cluster)
            print(name)
            location = location + (loop_count * 32)
        else:
            printByHex(dir_name, NAME_SIZE)

        print('{:<30}'.format('Exts : '), end='')
        printByHex(ext, EXT_SIZE)
        print('{:<30}'.format('Attribute : '), end='')
        printByHex(attribute, ATTRIBUTE_SIZE)
        print('{:<30}'.format('NT Resource : '), end='')
        printByHex(nt_resource, NT_RESOURCE_SIZE)
        print('{:<30}'.format('Create Time Tenth : '), end='')
        printByHex(ctt, CREATE_TIME_TENTH_SIZE)
        print('{:<30}'.format('Create Time : '), end='')
        printByHex(ct, CREATE_TIME_SIZE)
        print('{:<30}'.format('Create Date : '), end='')
        printByHex(cd, CREATE_DATE_SIZE)
        print('{:<30}'.format('Late Access Date : '), end='')
        printByHex(lad, LATE_ACCESS_DATE_SIZE)
        print('{:<30}'.format('First Cluster High 2 Bytes  : '), end='')
        printByHex(fch2, FIRST_CLUSTER_HIGH_2_BYTE_SIZE)
        print('{:<30}'.format('Write Time : '), end='')
        printByHex(wt, WRITE_TIME_SIZE)
        print('{:<30}'.format('Write Date : '), end='')
        printByHex(wd, WRITE_DATE_SIZE)
        print('{:<30}'.format('First Cluster Low 2 bytes : '), end='')
        printByHex(fcl2, FIRST_CLUSTER_LOW_2_BYTE_SIZE)
        print('{:<30}'.format('File Size : '), end='')
        printByHex(fs, FILE_SIZE)
        print("\n\n\n")

        dir_cluster = dir_cluster[location:]

    print("------------------------------------------------------Root DIR------------------------------------------------------")

# parse function must be call an order or seeked Cuz drive seek.
if __name__ == "__main__":
    # /Users/janghanbin/Desktop/BoB7기/강대명 멘토님/fat32.dd
    file = "/Users/janghanbin/Desktop/BoB7기/강대명 멘토님/fat32.dd" # input("Input file path : ")
    if not file:
        print("Invaild file path. Please check your input.")
        exit(1)

    drive = open(file, "rb")
    # move file pointer to first. seek must be move sector size
    drive.seek(0)

    # parseCommentFAT return BPS, SPC
    bytes_per_sector, sector_per_cluster, reserved_sector = parseCommonFAT(drive)

    print("\n\n\n")
    root_dir_cluster, fat32_size = parseFAT32(drive)

    fat32_table_addr = reserved_sector * bytes_per_sector

    # parse first FAT32
    root_dir_cluster_list = parseRootDir(drive, fat32_table_addr, fat32_size, root_dir_cluster)

    # move to data section
    drive.seek((reserved_sector * bytes_per_sector) + ((fat32_size * bytes_per_sector) * 2)) # There is 2 FAT32 in FAT32 Area

    root_dir = drive.read(len(root_dir_cluster_list) * (sector_per_cluster * bytes_per_sector))  # parsing root

    parseDir(root_dir)