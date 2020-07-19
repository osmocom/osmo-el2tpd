osmo-el2tpd - Osmocom daemon for Ericsson L2TP
==============================================

This software is a daemon (server) for the L2TP dialect implemented
by the Ericsson SIU (Site Integration Unit) for means of carrying
the GSM A-bis interface over IP.

All code has been independently developed without any information or
assistance from Ericsson, merely by observing protocol traces between
the SIU 02 and whatever is the Ericsson-provided server side
implementation next to the BSC.

Warning: The code currently hard-codes 172.30.42.3 as the IP address
of the host running L2TPD.  Making this configurable is likely the
first thing you need to do before using it...
