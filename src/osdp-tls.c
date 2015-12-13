/*
  osdp-tls - TLS implementation of OSDP protocol

  Copyright 2015 Smithee,Spelvin,Agnew & Plinge, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/
#if 0
for CP

listen case:

done = 0
while not done
{
  set up for tls listen
  wait for connection
  when connected
    check for psk
    if psk ok start osdp reading
    else
      close connection
}

osdp reading
  if first contact send poll
  wait for io
    if read from tls
      send to osdp engine
    if HUP
      process command
    if timer
      send poll

  if data to send, send it

send case:
  while forever
  connect to PD
  send psk
  start timer
  wait for events
    if tls data
      process with osdp
    if HUP
      process command
  if data send it
  loop forever

for PD

listen case:

done = 0
while not done
{
  set up for tls listen
  wait for connection
  when connected
    check for psk
    if psk ok start osdp reading
    else
      close connection
}

osdp reading
  wait for io
    if read from tls
      send to osdp engine
    if HUP
      process command
  if data to send send it

send case:
  connect to CP
  send psk
  wait for event
    if tls data process it
    if HUP process command
  if data send it


#endif


#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <memory.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>



#include <gnutls/gnutls.h>


#include <osdp-tls.h>


void
  signal_callback_handler
    (int
      signum);


char
  buffer [MAX_BUF + 1];
OSDP_TLS_CONFIG
  config;
gnutls_dh_params_t
  dh_params;


int
  generate_dh_params
    (void)

{ /* generate_dh_params */

        unsigned int bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH,
                                                        GNUTLS_SEC_PARAM_LEGACY);
        /* Generate Diffie-Hellman parameters - for use with DHE
         * kx algorithms. These should be discarded and regenerated
         * once a day, once a week or once a month. Depending on the
         * security requirements.
         */
        gnutls_dh_params_init(&dh_params);
        gnutls_dh_params_generate2(dh_params, bits);

        return 0;
} /* generate_dh_params */


int
  initialize
    (OSDP_TLS_CONFIG
      *config)

{ /* initialize */

  char
    command [1024];
  int
    status;


  status = ST_OK;
  memset (config, 0, sizeof (*config));
  strcpy (config->version, "v0.00-EP02");
  strcpy (config->cert_file, "/tester/current/etc/osdp_tls_server_cert.pem");
  strcpy (config->key_file, "/tester/current/etc/osdp_tls_server_key.pem");
// read json config file
// sets role
config->role = OSDP_ROLE_CP;
// sets port
config->listen_sap = 10443;
strcpy (config->cmd_dir, "/tester/current/results");
sprintf (command, "mkdir -p %s/history",
  config->cmd_dir);
system (command);

  signal (SIGHUP, signal_callback_handler);
  return (status);

} /* initialize */


int
  main
    (int
      argc,
    char
      *argv [])

{ /* main for osdp-tls */

//  gnutls_anon_server_credentials_t anoncred;
  socklen_t
    client_len;
  int
    done;
  int
    done_tls;
  fd_set
    exceptfds;
  fd_set
    readfds;
  int
    sd;
  gnutls_session_t
    session;
  int
    listen_sd;
  int
    nfds;
  int
    optval;
  gnutls_priority_t
    priority_cache;
  struct sockaddr_in
    sa_cli;
  struct sockaddr_in
    sa_serv;
  const sigset_t
    sigmask;
  int
    status;
  int
    status_sock;
  int
    status_tls;
  struct timespec
    timeout;
  char
    topbuf [1024];
  fd_set
    writefds;
  gnutls_certificate_credentials_t
    x509_cred;


  status = ST_OK;
  done = 0;
  optval = 1;
  status = initialize (&config);
  fprintf (stderr, "osdp-tls version %s\n",
    config.version);
  if (status EQUALS ST_OK)
  if (config.role EQUALS OSDP_ROLE_CP)
    fprintf (stderr, "Role: CP\n");
  if (config.role EQUALS OSDP_ROLE_PD)
    fprintf (stderr, "Role: PD\n");
  fprintf (stderr, "Server certificate: %s\n",
    config.cert_file);
  fprintf (stderr, "        Server key: %s\n",
    config.key_file);
  {
    if (config.role EQUALS OSDP_ROLE_CP)
    {
fprintf (stderr, "CP\n");
      done = 0;
      while(!done)
      {
        if (gnutls_check_version ("3.1.4") == NULL)
        {
          fprintf (stderr,
             "GnuTLS 3.1.4 or later is required\n");
          status = -4;
        }
        /* for backwards compatibility with gnutls < 3.3.0 */
        gnutls_global_init ();
        gnutls_certificate_allocate_credentials (&x509_cred);
        status_tls =
          gnutls_certificate_set_x509_key_file(x509_cred, config.cert_file,
          config.key_file, GNUTLS_X509_FMT_PEM);
        if (status_tls < 0)
          status = ST_OSDP_TLS_NOCERT;

//        gnutls_anon_allocate_server_credentials (&anoncred);
        if (status EQUALS 0)
        {
          generate_dh_params ();
          gnutls_priority_init (&priority_cache,
            "PERFORMANCE:%SERVER_PRECEDENCE", NULL);
          gnutls_certificate_set_dh_params(x509_cred, dh_params);
          listen_sd = socket (AF_INET, SOCK_STREAM, 0);
          if (listen_sd EQUALS -1)
            status = -5;
        };
        if (status EQUALS 0)
        {
          memset (&sa_serv, '\0', sizeof(sa_serv));
          sa_serv.sin_family = AF_INET;
          sa_serv.sin_addr.s_addr = INADDR_ANY;
          sa_serv.sin_port = htons(config.listen_sap);
          setsockopt (listen_sd, SOL_SOCKET, SO_REUSEADDR, (void *) &optval,
            sizeof(int));
          status_sock = bind (listen_sd, (struct sockaddr *) &sa_serv, sizeof(sa_serv));
          if (status_sock EQUALS -1)
            status = -6;
        };
        if (status EQUALS 0)
        {
          status_sock = listen (listen_sd, 1024);
          if (status_sock EQUALS -1)
            status = -7;
        };
        if (status EQUALS 0)
        {
          fprintf (stderr,
            "Server ready. Listening to port '%d'.\n\n", config.listen_sap);
          client_len = sizeof (sa_cli);

          done_tls = 0;
            gnutls_init (&session, GNUTLS_SERVER);
            gnutls_priority_set(session, priority_cache);
            gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);
            sd = accept (listen_sd, (struct sockaddr *) &sa_cli, &client_len);
            fprintf (stderr, "- connection from %s, port %d\n",
              inet_ntop (AF_INET, &sa_cli.sin_addr, topbuf, sizeof (topbuf)),
              ntohs (sa_cli.sin_port));
            gnutls_transport_set_int (session, sd);
            do {
              status_tls = gnutls_handshake(session);
            } while (status_tls < 0 && gnutls_error_is_fatal (status_tls) == 0);
            if (status_tls < 0)
            {
              close (sd);
              gnutls_deinit (session);
              fprintf (stderr, "*** Handshake has failed (%s)\n\n",
                gnutls_strerror (status_tls));
              status = ST_OSDP_TLS_HANDSHAKE;
              done_tls = 1;
              done = 1;
              session = NULL;
            }
            if (status EQUALS ST_OK)
            {
              fprintf(stderr, "- Handshake was completed\n");

status_sock = fcntl (sd, F_SETFL,
  fcntl (sd, F_GETFL, 0) | O_NONBLOCK);
if (status_sock EQUALS -1)
{
  done_tls = 1;
  done = 1;
  status=-98;
};
          while (!done_tls)
{
              /*
                if there's known to be gnutls data, read it.
              */
              status_tls = gnutls_record_check_pending (session);
printf ("tls rcv pending %d\n",
  status_tls);
if (status_tls EQUALS GNUTLS_E_AGAIN)
  printf ("again\n");
                status_tls = gnutls_record_recv (session, buffer, MAX_BUF);
printf ("tls rcv %d\n",
  status_tls);
if (status_tls EQUALS GNUTLS_E_AGAIN)
  printf ("again 2\n");

              if (status_tls EQUALS 0)
              {
                nfds = 0;
                FD_ZERO (&readfds);
                FD_ZERO (&writefds);
                FD_ZERO (&exceptfds);
                timeout.tv_sec = 0;
                timeout.tv_nsec = 100000000l;
                status_sock = pselect (nfds, &readfds, &writefds, &exceptfds,
                  &timeout, &sigmask);
              }
              else
              {
                status_tls = gnutls_record_recv (session, buffer, MAX_BUF);
                if (status_tls EQUALS 0)
                  status = ST_OSDP_TLS_CLOSED;
                if (status_tls < 0)
                  status = ST_OSDP_TLS_ERROR;
                if (status EQUALS ST_OK)
                {
                  fprintf (stderr, "%d bytes received via TLS:\n",
                    status_tls);
                  fprintf (stderr, "%s\n",
                    buffer);
#if 0
    check for psk
    if psk ok start osdp reading
    else
      close connection
#endif
status = -99;
                }
              };
};
            };

            if (status != ST_OK)
            {
              done = 1;
              done_tls = 1;
            };

#if 0
                                gnutls_record_send(session, buffer, ret);
#endif
          if (status != ST_OK)
          {
            if (session != NULL)
            {
              gnutls_bye (session, GNUTLS_SHUT_WR);
              close (sd);
              gnutls_deinit(session);
            };
          };
        };
        if (status != ST_OK)
          done = 1;
      };
    };
    if (config.role EQUALS OSDP_ROLE_PD)
    {
fprintf (stderr, "PD\n");
status = -2;
    };
  };
  if (status != ST_OK)
    fprintf (stderr, "open-osdp return status %d\n",
      status);

  return (status);

} /* main for osdp-tls */


void
  process_current_command
    (void)

{ /*process_current_command */

  fprintf (stderr, "processing current command...\n");

} /*process_current_command */


void
  preserve_current_command
    (OSDP_TLS_CONFIG
      *cfg)

{ /* preserve_current_command */

  char
    command [1024];


  sprintf (command, "mv %s/osdp-tls_command.json %s/history/%02d_osdp-tls_command.json",
    cfg->cmd_dir,
    cfg->cmd_dir,
    cfg->cmd_hist_counter);
  system (command);
  cfg->cmd_hist_counter ++;
  if (cfg->cmd_hist_counter > 99)
    cfg->cmd_hist_counter = 0;

} /* preserve_current_command */


void
  signal_callback_handler
    (int
      signum)

{ /* signal_callback_handler */

  process_current_command ();
  preserve_current_command (&config);

  exit (signum);

} /* signal_callback_handler */

