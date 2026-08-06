SWITCH MONITOR
==============

Monitors your network switches and tells you when a port goes down, a link
gets saturated, or a cable starts producing errors.

Nothing to install. No account. No internet connection required.


STARTING IT
-----------

  Windows      double-click  "Start Switch Monitor.bat"
  Mac          double-click  "Start Switch Monitor.command"
  Linux        run           ./start-switch-monitor.sh

A black window opens and your browser opens to the dashboard. Leave the
black window open - closing it stops the monitoring.

If nothing happens, you need Python. It is free, from python.org/downloads.
On Windows, tick "Add Python to PATH" in the installer.


FIRST RUN
---------

1. Type your switch's IP address into "IP address or hostname".
2. Type its SNMP community string (often "public", but your network
   administrator may have set something else).
3. Click "Add switch".

It contacts the switch immediately. If the address or community string is
wrong, it tells you straight away rather than silently showing nothing.

Add as many switches as you like. They are remembered, so next time you
start the app it picks up where it left off.


WHAT YOU SEE
------------

Each switch shows every port: whether it is up, how fast the link is, how
much traffic is flowing, how heavily it is loaded, and the error count.

  UTILISATION   green under 70%, amber over 70%, red over 90%
  ERR/MIN       errors per minute - anything above zero in red is worth
                investigating. It usually means a bad cable, a failing
                SFP, or a duplex mismatch.

"Current problems" lists anything wrong right now. "Activity" is the
running history of things going wrong and recovering.

Traffic figures need two polls before they appear, so the first 30 seconds
will show dashes. That is normal.

"Save dashboard" writes a single HTML file you can email to someone.


IF A SWITCH WILL NOT CONNECT
----------------------------

Three causes, in the order they actually happen:

1. SNMP is not switched on the switch, or your computer's IP is not in
   the switch's allowed list. Most switches restrict SNMP by IP address.
2. The community string is wrong. A switch given a wrong community string
   stays completely silent - it does not send back an error - so this
   looks exactly like a network problem.
3. A firewall is blocking UDP port 161 between you and the switch.


TRYING IT WITHOUT A SWITCH
--------------------------

A simulated switch is built in, so you can see the app work before
pointing it at real equipment. Open a terminal in this folder and run:

    python3 netmon-app.py --simulate

Then add  127.0.0.1:11161  with community  public  in the dashboard.
The simulator deliberately misbehaves - one port flaps up and down, one
logs errors, one runs at full capacity - so you can watch alerts appear.


WHERE YOUR DATA LIVES
---------------------

A folder called SwitchMonitor in your home directory:

  Windows   C:\Users\<you>\SwitchMonitor
  Mac       /Users/<you>/SwitchMonitor
  Linux     /home/<you>/SwitchMonitor

It holds your switch list, the monitoring history, and an alerts log.
To remove the app completely, delete that folder and this one.


A NOTE ON SAFETY
----------------

This app only reads from your switches. It uses SNMP "get" requests and
never "set" requests, so it cannot change any switch's configuration.

The dashboard is only reachable from your own computer - it is not
published to the network.

Use a read-only SNMP community, and ask whoever runs your network to
restrict it to your computer's IP address.
