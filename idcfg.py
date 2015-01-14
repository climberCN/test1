#!/usr/bin/python
# -*- coding: utf-8 -*- 


import argparse
import subprocess
import json
import logging
from cmdutil import init_rotating_file_logger, calltrace, run_command, shell_call, ICIArgparser, \
    is_ha_env, my_spname, shell_call_rc, shell_call_rc_peer, parser_seqdata_dict, is_ha_env
	

logger = init_rotating_file_logger('/var/log/idcfg.log' )


def user_exit(args):								
    with open(r'/etc/passwd', 'r') as userfile:
        t_dict = dict()
        text = userfile.readlines()
        for tmp in text:
            tmp = tmp.strip()
            tmp = tmp.split(":")
            t_dict['username'] = tmp[0]
            t_dict['dir'] = tmp[5]
            t_dict['Uid'] = tmp[2]
            t_dict['Gid'] = tmp[3]
            if t_dict['username'] == args.u:
                return True
    return False
	
def group_exit(args):								
    with open(r'/etc/group', 'r') as groupfile:
        t_dict = dict()
        text = groupfile.readlines()
        for tmp in text:
            tmp = tmp.strip()
            tmp = tmp.split(":")
            t_dict['groupname'] = tmp[0]
            t_dict['Gid'] = tmp[2]
            if t_dict['groupname'] == args.g:
                return True
    return False

def print_error_message(out, message):
    if is_ha_env():
        print my_spname(),message
        print "\t",out
    else:
        print message
        print "\t",out
    
def cmd_add_local(args):
    if int(args.U) <= 99 or int(args.U) >= 60000:
        print "Uid allowed is 100 to 60000,user add failed"
        exit()
    if args.g and not group_exit(args):
        cmd = "/usr/sbin/groupadd "
        cmd += ("-g %s " % args.G) if args.G else ""
        cmd += ("%s " %args.g)
        out, rc = shell_call_rc(cmd)
        if rc != 0:
            print_error_message(out, "haven't add group, add user, set passwd or set home_dir")
            exit(rc)
    
    if user_exit(args):
        exit("user exits")
        
    cmd = "/usr/sbin/useradd "
    cmd += ("-u %s " % args.U) if args.U else ""
    cmd += ("-g %s " % args.g) if args.g else ""
    cmd += ("-G %s " % args.G) if args.G else ""
    cmd += ("%s " % args.u)
    out,rc = shell_call_rc(cmd)
    if rc != 0:
        print_error_message(out, "haven't add user, set passwd or set home_dir")
        exit(rc)

    if args.p:
        cmd = "/usr/sbin/chpwd "
        cmd += ("%s " % args.u) if args.u else ""
        cmd += ("%s " % args.p) if args.p else ""
        out, rc = shell_call_rc(cmd)
        if rc != 0:
            print_error_message(out, "haven't set passwd")
            
    if args.d:
        cmd = "/usr/lib/passmgmt "
        cmd += ("-m -h %s " % args.d) if args.d else ""
        cmd += ("%s " % args.u) if args.u else ""
        out, rc = shell_call_rc(cmd)
        if rc != 0:
            print_error_message(out, "haven't set home_dir")
            


def cmd_add_remote(args):
    cmd = "/root/idcfg add -local "
    cmd += ("-u %s " % args.u) if args.u else ""
    cmd += ("-U %s " % args.U) if args.U else ""
    cmd += ("-g %s " % args.g) if args.g else ""
    cmd += ("-G %s " % args.G) if args.G else ""
    cmd += ("-d %s " % args.d) if args.d else ""
    cmd += ("-p %s " % args.p) if args.p else ""
    out, rc = shell_call_rc_peer(cmd)
    if rc != 0:
        print_error_message(out, "remote operation failed")
        exit(rc)
			
def cmd_add(args):
    cmd_add_local(args)
    if is_ha_env() and not args.local:
        cmd_add_remote(args)


	

def cmd_list(args):									
    with open(r'/etc/passwd', 'r') as userfile:
        t_dict = dict()
        user_list = list()
        text = userfile.readlines()
        for tmp in text:
            tmp = tmp.strip()
            tmp = tmp.split(":")
            t_dict['username'] = tmp[0]
            t_dict['dir'] = tmp[5]
            t_dict['Uid'] = tmp[2]
            t_dict['Gid'] = tmp[3]
            user_list.append(t_dict.copy())
    print "\n"
    print "Users:"
    print "%-20s%-8s%-8s%-8s" %('userName','Uid','Gid','Dir')
    for tmp in user_list:
        if int(tmp['Uid']) >= 99 and int(tmp['Uid']) <= 60000:
            print "%-20s%-8s%-8s%-20s" %(tmp['username'], tmp['Uid'], tmp['Gid'], tmp['dir'])
	
    with open(r'/etc/group', 'r') as groupfile:
        t_dict = dict()
        group_list = list()
        text = groupfile.readlines()
        for tmp in text:
            tmp = tmp.strip()
            tmp = tmp.split(":")
            t_dict['groupname'] = tmp[0]
            t_dict['Gid'] = tmp[2]
            group_list.append(t_dict.copy())
    print "\n\n"
    print "Groups:"
    print "%-15s%-8s" %("groupName", "Gid")
    for tmp in group_list:
        if int(tmp['Gid']) >= 99 and int(tmp['Gid']) <= 60000:
            print "%-15s%-8s" %(tmp['groupname'], tmp['Gid'])
    print "\n"

	
def cmd_modify_local(args):
    if args.p:
        cmd = "/usr/sbin/chpwd "
        cmd += ("%s " % args.u) if args.u else ""
        cmd += ("%s " % args.p) if args.p else ""
        out,rc = shell_call_rc(cmd)
        if rc != 0:
            if is_ha_env():
                print my_spname(),"haven't change the passwd"
                print "\t",out
            else:
                print "haven't change the passwd"
                print "\t",out
    if args.d:
        cmd = "/usr/lib/passmgmt "
        cmd += ("-m -h %s " % args.d) if args.d else ""
        cmd += ("%s " % args.u) if args.u else ""
        out, rc = shell_call_rc(cmd)
        if rc != 0:
            if is_ha_env():
                print my_spname(),"haven't change the home_dir"
                print "\t",out
            else:
                print "haven't change the home_dir"
                print "\t",out

def cmd_modify_remote(args):
    cmd = "/root/idcfg modify -local "
    cmd += ("-u %s " % args.u) if args.u else ""
    cmd += ("-p %s " % args.p) if args.p else ""
    cmd += ("-d %s " % args.d) if args.d else ""
    out, rc = shell_call_rc_peer(cmd, quiet = False)
    if rc != 0:
        print_error_message(out, "remote modify failed")
        exit(rc)
            
def cmd_modify(args):
    if is_ha_env() and not args.local:
        cmd_modify_remote(args)
    cmd_modify_local(args)

			
def cmd_del_local(args):
    cmd = "/usr/sbin/userdel "
    cmd += ("%s" %args.u)
    out, rc = shell_call_rc(cmd)
    if rc != 0:
        if is_ha_env():
            print my_spname(),"haven't delete user"
            print "\t",out
        else:
            print "haven't delete user"
            print "\t",out
        
        
def cmd_del_remote(args):
    cmd = "/root/idcfg del -local "
    cmd += ("-u %s " %args.u) if args.u else ""
    out, rc = shell_call_rc_peer(cmd, quiet = False)
    if rc != 0:
        print my_spname(),"remote delete user failed"
        print "\t",out

        

def cmd_del(args):
    if is_ha_env() and not args.local:
        cmd_del_remote(args)
    cmd_del_local(args)
		
def main():	
    parser = argparse.ArgumentParser(prog = 'idcfg', usage = "\n    idcfg list\n\
    idcfg add <-u username [-U uid] [-g group [-G gid]] |  -g group [-G gid]> [-p password] [-d home_dir]\n\
    idcfg modify <-u username > [-p password|-] [-d home_dir]\n\
    idcfg del <-u username>")
    subparser = parser.add_subparsers()

    parser_list = subparser.add_parser('list', help = "list user and group")
    parser_list.set_defaults(func = cmd_list)
    
    parser_add = subparser.add_parser('add', help = "add user")
    parser_add.add_argument('-u', help = "username", required = True)
    parser_add.add_argument('-U', help = "Uid")
    parser_add.add_argument('-g', help = "groupname")
    parser_add.add_argument('-G', help = "Gid")
    parser_add.add_argument('-d', help = "home_dir")
    parser_add.add_argument('-p', help = "passwd")
    parser_add.add_argument('-local', help = "add user at local", action = "store_true")
    parser_add.set_defaults(func = cmd_add)
    
    parser_modify = subparser.add_parser('modify', help = "modify passwd or modify home_dir")
    parser_modify.add_argument('-u', help = "username", required = True)
    parser_modify.add_argument('-p', help = "passwd")
    parser_modify.add_argument('-d', help = "home_dir")
    parser_modify.add_argument('-local', help = "modify at local", action = "store_true")
    parser_modify.set_defaults(func = cmd_modify)
    
    parser_del = subparser.add_parser('del', help = "delete user")
    parser_del.add_argument('-u', help = "username", required = True)
    parser_del.add_argument('-local', help = "del user at local", action = "store_true")
    parser_del.set_defaults(func = cmd_del)
    
    args = parser.parse_args()
    args.func(args)
    
	
if __name__ == "__main__":
    main()