/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "maild.h"
#include "mail_list.h"

/* GDB: set follow-fork-mode child */
#define MAIL_DEBUG_FLAG     0
#define MAIL_DEBUG(x,y,z) if(MAIL_DEBUG_FLAG) merror(x,y,z)

#ifndef ARGV0
#define ARGV0 "ossec-maild"
#endif

/* Global variables */
unsigned int mail_timeout;
unsigned int   _g_subject_level;
char _g_subject[SUBJECT_SIZE + 2];

/* Prototypes */
static void OS_Run(MailConfig *mail) __attribute__((nonnull)) __attribute__((noreturn));
static void help_maild(void) __attribute__((noreturn));


/* Print help statement */
static void help_maild()
{
    print_header();
    print_out("  %s: -[Vhdtf] [-u user] [-g group] [-c config] [-D dir]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -u <user>   User to run as (default: %s)", MAILUSER);
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -c <config> Configuration file to use (default: %s)", DEFAULTCPATH);
    print_out("    -D <dir>    Directory to chroot into (default: %s)", DEFAULTDIR);
    print_out(" ");
    exit(1);
}

int main(int argc, char **argv)
{
    int c, test_config = 0, run_foreground = 0;
    uid_t uid;
    gid_t gid;
    const char *dir  = DEFAULTDIR;
    const char *user = MAILUSER;
    const char *group = GROUPGLOBAL;
    const char *cfg = DEFAULTCPATH;

    /* Mail Structure */
    MailConfig mail;

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "Vdhtfu:g:D:c:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_maild();
                break;
            case 'd':
                nowDebug();
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'u':
                if (!optarg) {
                    ErrorExit("%s: -u needs an argument", ARGV0);
                }
                user = optarg;
                break;
            case 'g':
                if (!optarg) {
                    ErrorExit("%s: -g needs an argument", ARGV0);
                }
                group = optarg;
                break;
            case 'D':
                if (!optarg) {
                    ErrorExit("%s: -D needs an argument", ARGV0);
                }
                dir = optarg;
                break;
            case 'c':
                if (!optarg) {
                    ErrorExit("%s: -c needs an argument", ARGV0);
                }
                cfg = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            default:
                help_maild();
                break;
        }
    }

    /* Start daemon */
    debug1(STARTED_MSG, ARGV0);

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        ErrorExit(USER_ERROR, ARGV0, user, group);
    }

    /* Read configuration */
    if (MailConf(test_config, cfg, &mail) < 0) {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }

    /* Read internal options */
    mail.strict_checking = getDefine_Int("maild",
                                         "strict_checking",
                                         0, 1);

    /* Get groupping */
    mail.groupping = getDefine_Int("maild",
                                   "groupping",
                                   0, 2);

    /* Get subject type */
    mail.subject_full = getDefine_Int("maild",
                                      "full_subject",
                                      0, 1);

#ifdef LIBGEOIP_ENABLED
    /* Get GeoIP */
    mail.geoip = getDefine_Int("maild",
                               "geoip",
                               0, 1);
#endif

    /* Exit here if test config is set */
    if (test_config) {
        exit(0);
    }

    if (!run_foreground) {
        nowDaemon();
        goDaemon();
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        ErrorExit(SETGID_ERROR, ARGV0, group, errno, strerror(errno));
    }

    if (mail.smtpserver[0] != '/') {
        /* chroot */
        if (Privsep_Chroot(dir) < 0) {
            ErrorExit(CHROOT_ERROR, ARGV0, dir, errno, strerror(errno));
        }
        nowChroot();
        debug1(CHROOT_MSG, ARGV0, dir);
    }

    /* Change user */
    if (Privsep_SetUser(uid) < 0) {
        ErrorExit(SETUID_ERROR, ARGV0, user, errno, strerror(errno));
    }

    debug1(PRIVSEP_MSG, ARGV0, user);

    /* Signal manipulation */
    StartSIG(ARGV0);

    /* Create PID files */
    if (CreatePID(ARGV0, getpid()) < 0) {
        ErrorExit(PID_ERROR, ARGV0);
    }

    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());

    /* The real daemon now */
    OS_Run(&mail);
}

/* Read the queue and send the appropriate alerts
 * Not supposed to return
 */
static void OS_Run(MailConfig *mail)
{
    MailMsg *msg;
    MailMsg *s_msg = NULL;
    MailMsg *msg_sms = NULL;

    time_t tm;
    struct tm *p;

    int i = 0;
    int mailtosend = 0;
    int childcount = 0;
    int thishour = 0;
    int flush_grouped = 0;

    int n_errs = 0;

    file_queue *fileq;

    /* Get current time before starting */
    tm = time(NULL);
    p = localtime(&tm);
    thishour = p->tm_hour;

    /* Initialize file queue */
    i = 0;
    i |= CRALERT_MAIL_SET;
    os_calloc(1, sizeof(file_queue), fileq);
    Init_FileQueue(fileq, p, i);

    /* Create the list */
    OS_CreateMailList(MAIL_LIST_SIZE);

    /* Set default timeout */
    mail_timeout = DEFAULT_TIMEOUT;

    /* Clear global variables */
    _g_subject_level = 0;
    _group_alertcount = 1;
    memset(_g_subject, '\0', SUBJECT_SIZE + 2);
    memset(_group_subject, '\0', SUBJECT_SIZE +2);

    while (1) {
        tm = time(NULL);
        p = localtime(&tm);

        /* SMS messages are sent without delay */
        if (msg_sms) {
            pid_t pid;

            pid = fork();

            if (pid < 0) {
                merror(FORK_ERROR, ARGV0, errno, strerror(errno));
                sleep(30);
                continue;
            } else if (pid == 0) {
                if (OS_Sendsms(mail, p, msg_sms) < 0) {
                    merror(SNDMAIL_ERROR, ARGV0, mail->smtpserver);
                }

                exit(0);
            }

            /* Free SMS structure */
            FreeMailMsg(msg_sms);
            msg_sms = NULL;

            /* Increase child count */
            childcount++;
        }

        /* If mail_timeout == NEXTMAIL_TIMEOUT, we will try to get
         * more messages, before sending anything
         */
        if ((mail_timeout == NEXTMAIL_TIMEOUT) && (p->tm_hour == thishour)) {
            /* Get more messages */
        }

        /* Hour changed: send all supressed mails */
        else if ((mailtosend < mail->maxperhour) ||
                 ((p->tm_hour != thishour) && (childcount < MAXCHILDPROCESS))) {
            MailNode *mailmsg;
            pid_t pid;

            /* Check if we have anything to send */
            mailmsg = OS_CheckLastMail();
            if (mailmsg == NULL) {
                /* Don't fork in here */
                goto snd_check_hour;
            }
            if(mail->gran_to)
            {
                i = 0;
                while(mail->gran_to[i] != NULL)
                {
                    if (mail->gran_set[i] > 0)
                    {
                        MAIL_DEBUG("Mail DEBUG send mail: mailto %s -> %i", mail->gran_to[i], mail->gran_set[i]);
                    }
                    i++;
                }
            }
            pid = fork();
            if (pid < 0) {
                MAIL_DEBUG("Mail DEBUG send mail: fork failed %s %s", "", "");
                merror(FORK_ERROR, ARGV0, errno, strerror(errno));
                sleep(30);
                continue;
            } else if (pid == 0) {
                if(mail->groupping == 2)
                {
                    memset(_g_subject, '\0', SUBJECT_SIZE +2);
                    if((_group_alertcount > 1) && (_group_subject[0] != '\0'))
                    {
                        if (strlen(_group_subject) > SUBJECT_SIZE -17)
                        {
                            strncpy(_g_subject, _group_subject, SUBJECT_SIZE-21);
                            snprintf(_group_subject,SUBJECT_SIZE -17,"%s....", _g_subject);
                            memset(_g_subject, '\0', SUBJECT_SIZE +2);
                        }
                        snprintf(_g_subject, SUBJECT_SIZE -1, MULTIPLE_ALERTS, _group_subject, _group_alertcount);
                    }
                    else
                    {
                        strncpy(_g_subject, _group_subject, SUBJECT_SIZE);
                    }
                }
                if(p->tm_hour != thishour && mailtosend >= mail->maxperhour)
                {
                    snprintf(_g_subject, SUBJECT_SIZE -1, HOURLY_SUBJECT, _group_alertcount);
                }
                if (OS_Sendmail(mail, p) < 0) {
                    merror(SNDMAIL_ERROR, ARGV0, mail->smtpserver);
                }

                exit(0);
            }

            /* increase mail counter */
            mailtosend++;

            /* Clean the memory */
            mailmsg = OS_PopLastMail();
            do {
                FreeMail(mailmsg);
                mailmsg = OS_PopLastMail();
            } while (mailmsg);

            /* Increase child count */
            childcount++;

            /* Clear global variables */
            _g_subject[0] = '\0';
            _g_subject[SUBJECT_SIZE - 1] = '\0';
            _g_subject_level = 0;

            _group_alertcount = 1;
            _group_subject[0] = '\0';
            _group_subject[SUBJECT_SIZE -1] = '\0';

            /* Clean up set values */
            if (mail->gran_to) {
                MAIL_DEBUG("Mail DEBUG send mail: resetting mailto %s %s", "", "");
                i = 0;
                while (mail->gran_to[i] != NULL) {
                    if(s_msg && mail->gran_tmp_set[i] == DONOTGROUP)
                    {
                        mail->gran_tmp_set[i] = FULL_FORMAT;
                    }
                    mail->gran_set[i] = 0;
                    i++;
                }
            }

snd_check_hour:
            /* If we sent everything */
            if (p->tm_hour != thishour) {
                thishour = p->tm_hour;

                mailtosend = 0;
            }
        }

        /* Saved message for the do_not_group option */
        if (s_msg) {
            i = 0;
            while(mail->gran_to[i] != NULL)
            {
                if (mail->gran_tmp_set[i] > 0)
                {
                    MAIL_DEBUG("Mail DEBUG smsg loop: copying to gran_set: %s %i", mail->gran_to[i], mail->gran_tmp_set[i] );
                    mail->gran_set[i] = mail->gran_tmp_set[i];
                }
                i++;
            }
            /* Set the remaining do no group to full format */
            if (mail->gran_to) {
                i = 0;
                while (mail->gran_to[i] != NULL) {
                    if (mail->gran_set[i] == DONOTGROUP) {
                        mail->gran_set[i] = FULL_FORMAT;
                    }
                    i++;
                }
            }

            OS_AddMailtoList(s_msg);

            /* flush_grouped is set when mail is grouped by subject */
            if(flush_grouped > 0)
            {
                strncpy(_group_subject, s_msg->subject, SUBJECT_SIZE);
                s_msg = NULL;
                /* this is a priority message, flush the email queue again */
                if(flush_grouped == 2)
                {
                    flush_grouped = 0;
                    continue;
                }
                flush_grouped = 0;
            }
            else
            { /* normal behavior, only skip if we are grouping by subject */
                 s_msg = NULL;
                continue;
            }
        }

        /* Receive message from queue */
        if ((msg = OS_RecvMailQ(fileq, p, mail, &msg_sms)) != NULL) {
            /* If we are < max emails per hour then count the mails grouped by subject
               If we are > max emails per hour then count all mails
            */
            if((mailtosend >= mail->maxperhour)||
                ((mail->groupping == 2) && (strncmp(_group_subject, msg->subject, SUBJECT_SIZE) == 0 )))
            {
                _group_alertcount++;
            }
            /* If the e-mail priority is do_not_group,
             * flush all previous entries and then send it.
             * Use s_msg to hold the pointer to the message while we flush it.
             */
            if (mail->priority == DONOTGROUP) {
                s_msg = msg;
            } else {
                if(mail->groupping == 2)
                {
                    /* check if we can group this mesage with the last one */
                    if (strncmp(_group_subject, msg->subject, SUBJECT_SIZE) == 0 )
                    {
                        debug1("%s: grouping mail with subject '%s'", ARGV0, msg->subject);
                        i = 0;
                        while(mail->gran_to[i] != NULL)
                        {
                            if (mail->gran_tmp_set[i] > 0)
                            {
                                MAIL_DEBUG("Mail DEBUG main loop: copying to gran_set: %s %i", mail->gran_to[i], mail->gran_tmp_set[i] );
                                mail->gran_set[i] = mail->gran_tmp_set[i];
                            }
                            i++;
                        }
                        OS_AddMailtoList(msg);
                    }
                    else
                    {
                        debug1("%s: new mail queue with subject '%s'", ARGV0, msg->subject);
                        /* first flush email queue, then add current messagt to the empty queue */
                        s_msg = msg;
                        /* we are going to flush any mails in the queue but have to remember how this specific email has to be handled afterwards */
                        if(mail->priority)
                        {
                            /* priority mail, send directly after queue is flushed */
                            flush_grouped = 2;
                        }
                        else
                        {
                            flush_grouped = 1;
                        }
                        mail_timeout = DEFAULT_TIMEOUT;
                        continue;
                    }
                }
                else
                { /* no grouping of emails, or global grouping of emails */
                    OS_AddMailtoList(msg);
                }
            }

            /* Change timeout to see if any new message is coming shortly */
            if(mail->groupping > 0) {
                /* If priority is set, send email now */
                if (mail->priority) {
                    mail_timeout = DEFAULT_TIMEOUT;
                } else {
                    /* 5 seconds only */
                    mail_timeout = NEXTMAIL_TIMEOUT;
                }
            }
        } else {
            if (mail_timeout == NEXTMAIL_TIMEOUT) {
                /* Default timeout */
                mail_timeout = DEFAULT_TIMEOUT;
            }
        }

        /* Wait for the children */
        while (childcount) {
            int wp;
            int p_status;
            wp = waitpid((pid_t) - 1, &p_status, WNOHANG);
            if (wp < 0) {
                merror(WAITPID_ERROR, ARGV0, errno, strerror(errno));
                n_errs++;
            }

            /* if = 0, we still need to wait for the child process */
            else if (wp == 0) {
                break;
            } else {
                if (p_status != 0) {
                    merror(CHLDWAIT_ERROR, ARGV0, p_status);
                    merror(SNDMAIL_ERROR, ARGV0, mail->smtpserver);
                    n_errs++;
                }
                childcount--;
            }

            /* Too many errors */
            if (n_errs > 6) {
                merror(TOOMANY_WAIT_ERROR, ARGV0);
                merror(SNDMAIL_ERROR, ARGV0, mail->smtpserver);
                exit(1);
            }
        }

    }
}

