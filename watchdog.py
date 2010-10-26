#!/usr/bin/python
#
# Copyright 2010 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may abtain a copy of the license at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""WatchDog.

This program monitors resources of Linux systems.

Classes:

  Monitor - The Monitor is responsible for managing the overall process of
  keeping an updated status of each host.

  MonitorThread - a very small threaded class that gets hosts from a queue and
  will create a RemoteWorker object for each thread.

  RemoteWorker - responsible for SSHing to remote hosts to gather resources.

  Resource - maintains all of the resources that are monitored, and methods to
  parse their data for consumption by RRDTool.

  RRD - maintains all interfaces to RRDTool, including graph definitions, and
  methods to create, update, and graph resources.

  TestBed - a global class used to hold configuration data and data collected
  from each remote host. Additionally, formatted data for RRD will be kept
  associated with each host, and some general information about the update
  process of each remote host.

  TBQueue - a subclass of Queue.Queue(), in order to override method join(),
  since we need a timeout in case one of the paramiko ssh sessions hangs.

Dependencies:

  WatchDog depends on a few external programs beign installed. Mainly:
    - python - written in python, so we're dead without it.
    - lshw - uses to get an inventory and determine network devices.
    - RRDTool - used to created graphs/charts of monitored resources.
    - dmidecode - used to get bios and system info.
  You also need to have all of the client machines setup for ssh without a
  password (as root). To set that up, simply generate a public keypair:
    - ssh-keygen -t rsa
    - copy public key to target host and append to .ssh/authorized_keys
    - see http://linuxproblem.org/art_9.html for more details.

Usage:
  The following options are supported:
  --conffile: the name of the configuration file. Default: watchdog.yaml.
  --debug: set the debug level. Requires one of the following parameters:
      debug
      info (default)
      warning
      error
      critical
  --graph: boolean, if True, it will create new graphs for resources.
  --html: boolean, if set to True it will build html pages.
  --log_to_stdout: send program output to stdout as well as logs.
  --logfile: set the file name of the log file. Default: watchdog.log
  --testbed: the name of the testbed to use. Default: default.
  --update: boolean, if True, it will collect new data from all monitored
    hosts, and update the RRD databases with the newly collected data.

  Arguments should be space separated.
"""

__author__ = 'kdlucas@gmail.com (Kelly Lucas)'
__version__ = '2.04'

import logging, logging.handlers, optparse, os, paramiko, Queue, shutil
import subprocess, sys, threading, yaml
from IPy import IP
from time import *

TIMEOUT = 5  # Timeout for accessing remote hosts.
RUNTIME = 240  # Total time to allow the host queue to finish all tasks.

def SetLogger(namespace, logfile, loglevel, log_to_stdout=False):
  """Create a log handler and set log level.

  Args:
    namespace: name of the logger.
    logfile: log file name.
    loglevel: debug level of logger.
    log_to_stdout: boolean, True = send msgs to stdout and logfile,
                            False = send msgs to log file only.
  Returns:
    Logger object.
  We use RotatingFileHandler to handle rotating the log files when they reach
  maxsize in bytes.
  """
  MAXSIZE = 8192000  # Max size to grow log files, in bytes.

  levels = {'debug': logging.DEBUG,
            'info': logging.INFO,
            'warning': logging.WARNING,
            'error': logging.ERROR,
            'critical': logging.CRITICAL,
           }

  logger = logging.getLogger(namespace)
  c = logging.StreamHandler()
  h = logging.handlers.RotatingFileHandler(logfile, maxBytes=MAXSIZE,
                                           backupCount=10)
  hf = logging.Formatter('%(asctime)s %(process)d %(levelname)s: %(message)s')
  cf = logging.Formatter('%(levelname)s: %(message)s')
  logger.addHandler(h)
  h.setFormatter(hf)
  if log_to_stdout:
    logger.addHandler(c)
    c.setFormatter(cf)

  logger.setLevel(levels.get(loglevel, logging.INFO))

  return logger


class MonitorThread(threading.Thread):
  """Get AutoTest hosts from queue and create remote host monitors."""

  def __init__(self):
    threading.Thread.__init__(self)
    self.tb = TB  # In case the thread outlives the main program.


  def run(self):
    host = self.tb.q.get()
    worker = RemoteWorker(host.hostname)
    try:
      worker.run()
    except Exception, e:
      self.tb.logger.error('Error on remote host: %s\n%s', self.h, e)
    # Notify Queue that process is finished.
    self.tb.logger.debug('Releasing host %s from queue', host.hostname)
    self.tb.q.task_done()


class RemoteWorker(object):
  """SSH into remote hosts to obtain resource data."""

  def __init__(self, hostname):
    """
    Args:
      hostname: string, hostname of AutoTest host.
    """
    self.h = hostname
    self.cmds = {'bios': ['dmidecode -t 0',
                          ['Vendor', 'Version', 'Release Date']],
                 'model': ['dmidecode -t 1',
                           ['Manufacturer', 'Product Name']],
                }
    self.client = paramiko.SSHClient()
    self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    self.tb = TB  # In case the thread outlives the main program.
    # Send paramiko messages to our log file.
    self.logger = SetLogger('SSH', self.tb.sshlog, self.tb.loglevel)
    paramiko.util.log_to_file(self.tb.sshlog, level=30)


  def run(self):
    try:
      self.client.connect(self.h, username='root', key_filename=self.tb.privkey,
                          timeout=TIMEOUT)
      self.logger.info('Connected to host %s', self.h)
      self.tb.hosts[self.h]['status'] = True
    except Exception, e:
      self.logger.error('Host %s: %s', self.h, e)
      self.tb.hosts[self.h]['status'] = False
    finally:
      if self.tb.hosts[self.h]['status']:
        try:
          self.GetInventory()
          self.ReadRelease()  # Must be done before UpdateRelease().
          for k in self.cmds:
            self.RunCommand(k, self.cmds[k][0], self.cmds[k][1])
        except Exception, e:
          self.logger.error('Error on : %s\n%s', self.h, e)
      self.UpdateRelease()  # Must be done before ReadResources().
      if self.tb.hosts[self.h]['status']:
        try:
          self.ReadResources()
        except Exception, e:
          self.tb.logger.error('Error on: %s\n%s', self.h, e)
      self.tb.logger.debug('Closing client for %s', self.h)
      self.client.close()
    self.tb.hosts[self.h]['time'] = strftime('%d%b%Y %H:%M:%S', localtime())


  def ReadRelease(self):
    """Get the Linux Release version."""
    # The PTR key will mark the current version, version history is preserved.

    release = []
    cmd = 'cat /etc/issue'
    try:
      stdin, stdout, stderr = self.client.exec_command(cmd)
      for line in stdout:
        if len(line) > 2:
          release.append(line[:-7].strip())
    except Exception, e:
      self.tb.logger.error('Error getting release version on %s\n%s', self.h, e)
    release.append('-->')
    cmd = 'uname -r'
    try:
      stdin, stdout, stderr = self.client.exec_command(cmd)
      for line in stdout:
        release.append(line.strip())
    except Exception, e:
      self.tb.logger.error('Error getting kernel version on %s\n%s', self.h, e)

    if release:
      self.tb.hosts[self.h]['release']['PTR'] = "".join(release)


  def RunCommand(self, item, cmd, targets):
    """Get the Firmware versions."""
    # The PTR key will mark the current versions.
    val = []
    try:
      stdin, stdout, stderr = self.client.exec_command(cmd)
      for line in stdout:
        if any (t in line for t in targets):
          fields = line.split(':')
          # We must sanitize the string for RRDTool.
          val.append(fields[1].strip('\n" '))
      self.tb.hosts[self.h][item]['PTR'] = " ".join(val)
    except Exception, e:
      self.tb.logger.error('Error running remote cmd on %s\n%s', self.h, e)


  def GetFS(self):
    """Find filesystems and add device and mount point to Resource.fs

    Returns: dictionary of filesystem devices and mount points.
    """
    fs = {}
    cmd = 'df -P -x tmpfs -x debugfs -x devtmpfs -l'
    try:
      stdin, stdout, stderr = self.client.exec_command(cmd)
      for line in stdout:
        if line.startswith('/dev'):
          fields = line.split()
          if len(fields) > 5:
            fs[fields[0]] = fields[5]
    except Exception, e:
      self.tb.logger.error('Error getting file systems on %s\n%s', self.h, e)

    # If we are using LVM, we need to replace the device mapper with the dm
    # device used in /proc/diskstats.
    for k in fs:
      if '/dev/mapper' in k:
        cmd = 'ls -l %s' % k
        try:
          stdin, stdout, stderr = self.client.exec_command(cmd)
          for line in stdout:
            fields = line.split()
            device_minor = fields[5]
            device = 'dm-%s' % device_minor
            fs[device] = fs[k]
            del fs[k]
        except Exception, e:
          self.tb.logger.error('Error getting device mapper minor number.')
          self.tb.logger.error(e)

    return fs

            
  def GetNetDevs(self):
    """Get all of the network devices.

    Returns: list of network devices.
    """
    net_devs = []
    cmd = 'lshw -C network -short'
    try:
      stdin, stdout, stderr = self.client.exec_command(cmd)
      for line in stdout:
        if line.startswith('/'):
          fields = line.split()
          net_devs.append(fields[1])
    except Exception, e:
      self.tb.logger.error('Error getting network devices\n%s', e)

    return net_devs


  def GetInventory(self):
    """Get the basic hardware details of the system."""
    cmd = 'lshw -html'
    try:
      stdin, stdout, stderr = self.client.exec_command(cmd)
    except Exception, e:
      self.tb.logger.error('Error taking inventory on host %s\n%s', self.h, e)
    self.tb.hosts[self.h]['hwinfo'] = stdout


  def UpdateRelease(self):
    """Update Release info with most current release versions.

    The PTR key points to the most recent released version. This will also
    preserve the last known release version in case the host is down.
    """
    rrd_dir = os.path.join(self.tb.home, 'hosts', self.h, 'rrd')
    hwinfo_file = os.path.join(rrd_dir, 'hwinfo.html')
    # Write the hardware info file
    try:
      hwf = open(hwinfo_file, 'w')
    except IOError, e:
      self.tb.logger.error('Error creating hwinfo file.\n%s', e)
    for line in self.tb.hosts[self.h]['hwinfo']:
      hwf.write(line)
    hwf.close()

    for v in self.tb.version:
      update_file = False
      relfile = os.path.join(rrd_dir, v)
      tmpfile = os.path.join(rrd_dir, v + '.tmp')
      if os.path.isfile(relfile):
        try:
          rf = open(relfile, 'r')
          lines = rf.readlines()
        except IOError, e:
          self.tb.logger.error('Error parsing release file %s\n%s', relfile, e)
        finally:
          rf.close()

        for line in lines:
          fields = line.split('=')
          # The correct format will have two strings separated by =.
          if len(fields) == 2:
            if fields[0] == 'PTR':
              if self.tb.hosts[self.h][v]['PTR']:
                if self.tb.hosts[self.h][v]['PTR'] != fields[1]:
                  # Most recent version has changed.
                  self.tb.logger.info('Release has been updated.')
                  self.tb.logger.info('New release: %s',
                                      self.tb.hosts[self.h][v]['PTR'])
                  update_file = True
                  lines.pop(lines.index(line))
                  self.tb.hosts[self.h][v][self.tb.time] = (
                      self.tb.hosts[self.h][v]['PTR'])
              else:
                # Host is down so use last known value.
                self.tb.hosts[self.h][v]['PTR'] = fields[1].srip()
            else:
              self.tb.hosts[self.h][v][fields[0]] = fields[1].strip()
          elif len(line) > 3:
            # This means the release file has the wrong format, so
            # we'll just write a new one with current values.
            update_file = True
            lines.pop(lines.index(line))
          else:
            # If we get here than it's probably a blank line.
            update_file = True
            lines.pop(lines.index(line))

        if update_file:
          self.tb.logger.debug('Updating %s', relfile)
          shutil.move(relfile, tmpfile)
          # Put the most recent update in the new file, and make the
          # PTR key to point to it.
          lines.append('%s=%s\n' % (self.tb.time,
                                    self.tb.hosts[self.h][v]['PTR']))
          lines.append('PTR=%s' % self.tb.hosts[self.h][v]['PTR'])
          try:
            rf = open(relfile, 'w')
            for line in lines:
              rf.write(line)
          except IOError, e:
            self.tb.logger.error('Error writing %s\n%s', relfile, e)
          finally:
            rf.close()
      else:
        # Create a new release file, as it does not exist.
        if self.tb.hosts[self.h][v]['PTR']:
          self.tb.logger.info('Creating new %s', relfile)
          try:
            rf = open(relfile, 'w')
            rf.write('%s=%s\n' % (
            self.tb.time,self.tb.hosts[self.h][v]['PTR']))
            rf.write('PTR=%s' % self.tb.hosts[self.h][v]['PTR'])
          except IOError, e:
            self.tb.logger.error('Error writing %s\n%s', relfile, e)
          finally:
            rf.close()

          self.tb.hosts[self.h][v][self.tb.time] = (
              self.tb.hosts[self.h][v]['PTR'])


  def ReadResources(self):
    """Get resources that we are monitoring on the host."""

    filesystems = self.GetFS()
    net_devices = self.GetNetDevs()
    advisor = Resource(filesystems, net_devices)
    if self.tb.update == True:
      self.tb.logger.debug('Collecting data on %s', self.h)
      cmd = advisor.GetCommands()
      for r in advisor.resources:
        output = []
        try:
          stdin, stdout, stderr = self.client.exec_command(cmd[r])
          for line in stdout:
            output.append(line)
        except Exception, e:
          self.tb.logger.error('Cannot read %s from %s', r, self.h)
        self.tb.hosts[self.h]['data'][r] = "".join(output)
      self.tb.logger.debug('Formatting data for %s', self.h)
      advisor.FormatData(self.h)
    advisor.ProcessRRD(self.h)
    if self.tb.html:
      self.tb.logger.debug('Building HTML files for %s', self.h)
      advisor.BuildHTML(self.h)


class TestBed(object):
  """Used to hold all of the testbed machine data and some global varibles.

  This class will be instantiated as a global object so that all of the other
  classes in this module will have read/write access to it's variables. It
  will also hold some general configuration data as well as all remote hosts
  raw and formatted data that was collected.
  """

  def __init__(self, conffile, logfile, log_to_stdout, debug, graph, html,
               testbed, update):
    """
    Args:
      conffile: string, name of configuration file.
      logfile: string, name of logfile.
      log_to_stdout: boolean, True = send log msgs to stdout.
      debug: string, the debug log level.
      graph: boolean, flag to create graphs.
      html: boolean, flag to build html files.
      testbed: string, designates which testbed to use.
      update: boolean, flag to get update data from remote hosts.
    """
    self.version = ['bios', 'model', 'release']
    start_time = strftime('%H:%M:%S', localtime())
    self.time = int(time())

    # Add the watchdog directory to the configuration file, in case this is
    # being called from another directory.
    self.exec_dir = os.path.abspath(os.path.dirname(sys.argv[0]))
    conf_pathname = os.path.join(self.exec_dir, conffile)
    # Load configuration data from configuration file.
    ydict = self.ReadYamlFile(conf_pathname)
    # Get local site data from config file. 
    confdict = self.ReadConfig(ydict)
    self.caption = confdict['caption']
    self.home = confdict['homedir']
    self.privkey = confdict['privkey']
    rundir = confdict['rundir']
    self.url = confdict['urlhome']

    if not os.path.isdir(rundir):
      os.mkdir(rundir)
    self.update_runfile = os.path.join(rundir, 'update.running')
    self.graph_runfile = os.path.join(rundir, 'graph.running')
    self.logfile = os.path.join(self.home, logfile)
    self.sshlog = os.path.join(self.home, 'ssh.log')
    self.logger = SetLogger('SystemMonitor', self.logfile, debug,
                            log_to_stdout=log_to_stdout)
    self.logger.info('=================================================')
    self.logger.info('========            RUN START           =========')
    self.logger.info('=================================================')
    self.logger.info('Script started at: %s', start_time)

    self.loglevel = debug
    self.graph = graph
    self.html = html
    self.rrdtimes = ['-1hours', '-4hours', '-24hours', '-1week', '-1month',
                     '-1year']
    self.testbed = testbed
    self.update = update

    # tbhosts are Host objects from your testbed.. hosts hold the resource data.
    self.hosts = {}  # Dictionary to hold data from each host.
    self.tbhosts = self.LoadHosts(ydict, testbed)

    # Create a queue for checking resources on remote hosts.
    self.q = TBQueue()


  def ReadConfig(self, ydict):
    """Read configuration variables from config file.

    Args:
      ydict: dictionary of parsed yaml configuration file.
    Returns:
      dictionary of site values.
    """
    sitedict = {}
    for k in ydict['site']:
      sitedict.update(k)

    return sitedict


  def LoadHosts(self, ydict, testbed):
    """Load hosts from configuration file.

    Args:
      ydict: dictionary of parsed yaml configuration file.
      testbed: string, defines which testbed to use.
    Returns:
      list of Host objects.
    """
    hostlist = []
    if testbed in ydict['testbeds']:
      for s in ydict['testbeds'][testbed]:
        for k in s:
          hostlist.append(Host(k, s[k]))
        # Initialize host dictionary to hold data from testbed hosts.
        self.hosts[k] = {}
        self.hosts[k]['data'] = {}  # Raw data from hosts.
        self.hosts[k]['rrddata'] = {}  # Formatted data.
        self.hosts[k]['hwinfo'] = None
        self.hosts[k]['status'] = None
        self.hosts[k]['time'] = None
        for v in self.version:
          self.hosts[k][v] = {}
          self.hosts[k][v]['PTR'] = None
    else:
      self.logger.error('Could not find %s testbed in config file', testbed)

    return hostlist


  def ReadYamlFile(self, yamlfile):
    """Read a yaml file and return a dictionary tree of the data."""

    try:
      f = open(yamlfile, 'r')
      try:
        try:
          ydict = yaml.load(f)
        except IOError, e:
          self.logger.error('Error parsing %s\n%s', yamlfile, e)
      finally:
        f.close()
    except IOError, e:
      self.logger.error('Cannot open %s', yamlfile)

    return ydict


class Monitor(object):
  """Main class used to manage the monitoring of remote hosts.

  This class is used to determine the current status of hosts in the testbed.
  It will populate a queue from TestBed.tbhosts, and each host will be added
  to a Queue and start a threaded operation using the MonitorThread class, to
  access each host in the testbed and get resource data.
  """

  def __init__(self):
    """Monitor will use config data from TestBed."""
    self.threads = []


  def UpdateStatus(self):
    """Update data from all monitored hosts."""

    # Create new threads of class MonitorThread.
    self.hostqty = len(TB.tbhosts)
    for i in range(self.hostqty):
      t = MonitorThread()
      t.setDaemon(True)
      self.threads.append(t)
      t.start()

    # Fill the requests queue with AutoTest host objects.
    for host in TB.tbhosts:
      TB.logger.debug('Placing %s in host queue.', host.hostname)
      TB.q.put(host)


    if TB.graph:
      # Graphing takes much longer, so increase the max runtime.
      maxtime = RUNTIME * 6
    else:
      maxtime = RUNTIME
    # Queue.join() will wait for all jobs in the queue to finish, or
    # until the timeout value is reached.
    TB.logger.debug('Joining run queue.')
    TB.q.join(timeout=maxtime)
    TB.logger.info('%s hosts left in host queue', TB.q.qsize())
    TB.logger.info('Runtime is %d seconds', (time() - TB.time))

    LogLevel = TB.logger.getEffectiveLevel()
    if LogLevel == 10:
      for host in TB.tbhosts:
        TB.logger.debug('%s status is %s', host.hostname,
                         TB.hosts[host.hostname]['status'])

    # If there are any running threads, give them time to finish.
    # Since paramiko is multi threaded, this check is needed. A deadline
    # will be set since we don't want the process to run indefinitely.
    # A deadline needs to be set because one or more of the paramiko
    # threads could hang.
    deadline = time() + maxtime
    running = True
    while running:
      for t in self.threads:
        if t.isAlive():
          continue
        else:
          self.threads.remove(t)
      if len(self.threads) == 0:
        TB.logger.info('All threads have completed their jobs.')
        TB.logger.info('Runtime is %d seconds', (time() - TB.time))
        running = False
      else:
        TB.logger.debug('%d threads still running.', len(self.threads))
        sleep(TIMEOUT)
      waittime = deadline - time()
      if waittime < 0:
        TB.logger.info('Deadline reached. Aborting running threads.')
        TB.logger.info('%d threads still running!', len(self.threads))
        running = False


  def CheckStatus(self, hostname):
    """Check the status of one host.

    Args:
      hostname: hostname or ip address of host to check.
    This method is primarily used for debugging purposes.
    """
    t = MonitorThread()
    t.setDaemon(True)
    t.start()

    for host in TB.tbhosts:
      if host.hostname == hostname:
        TB.q.put(host)
        break
    TB.q.join(timeout=TIMEOUT)
    TB.logger.info('%s status is %s', hostname, TB.hosts[hostname]['status'])


  def ShowData(self):
    """Show raw data collected from each host."""

    for host in TB.tbhosts:
      TB.logger.info('Hostname: %s', host.hostname)
      for k in TB.hosts[host.hostname]['data']:
        TB.logger.info('%s: %s' , k, TB.hosts[host.hostname]['data'][k])


  def ValidIP(self, address):
    """Verify address is a valid IP address.

    Args:
      address: string.
    Returns:
      boolean: True = valid IP address, False = not valid IP address.
    """
    octets = address.split('.')
    if len(octets) != 4:
      return False
    for octet in octets:
      if not 0 <= int(octet) <= 255:
        return False
    return True


  def SortAFEHosts(self, afelist):
    """Sort AFE host list by IP address.

    Args:
      afelist: list of AFE host objects.
    Returns:
      newlist: list of sorted AFE host objects.
    """
    iplist = []
    hostlist = []

    for h in afelist:
      if self.ValidIP(h.hostname):
        iplist.append(h)
      else:
        hostlist.append(h)

    templist = [(IP(h.hostname).int(), h) for h in iplist]
    templist.sort()
    newlist = [h[1] for h in templist]
    hostlist.sort()
    newlist.extend(hostlist)

    return newlist


  def BuildLandingPage(self):
    """Build the initial HTML landing page with links to all hosts."""
    TB.logger.debug('Building Langing Page')
    sorted_ip = []
    sorted_hosts = []
    downhosts = 0
    readyhosts = 0
    sorted_ip = self.SortAFEHosts(TB.tbhosts)
    # Put host that are down first
    for h in sorted_ip:
      if not TB.hosts[h.hostname]['status']:
        sorted_hosts.insert(downhosts, h)
        downhosts = downhosts + 1
      else:
        sorted_hosts.append(h)
        readyhosts = readyhosts + 1

    # Create symlink to the log file if it does not exist.
    if TB.graph:
      log_filename = os.path.join(TB.home, 'graph.txt')
    else:
      log_filename = os.path.join(TB.home, 'update.txt')
    if not os.path.isfile(log_filename):
      try:
        os.symlink(TB.logfile, log_filename)
      except OSError, e:
        TB.logger.error('Error linking to logfile\n%s', e)
    sshlog = os.path.join(TB.home, 'ssh.txt')
    if not os.path.isfile(sshlog):
      os.symlink(TB.sshlog, sshlog)
    LandPageFile = os.path.join(TB.home, 'index.html')
    # The temp file is used so that there will always be viewable html page
    # when the new page is being built.
    LandPageTemp = os.path.join(TB.home, 'temp.html')
    f = open(LandPageTemp, 'w')
    f.write('<HTML><HEAD>')
    f.write('<LINK REL="stylesheet" TYPE="text/css" HREF="table.css">')
    f.write('<center><TITLE>System Health Check</TITLE></HEAD>')
    f.write('<BODY>')
    f.write('<img src="watchdog.png" style="float:left;"/>')
    f.write('<table style="float: right">')
    f.write('<TR><TD><em>Total Hosts</em><TD>%d' % (downhosts + readyhosts))
    f.write('<TR><TD><em>Inaccessible Hosts</em><TD>%d' % downhosts)
    f.write('<TR><TD><em>Accessible Hosts</em><TD>%d' % readyhosts)
    f.write('<TR><TD><em>Update Log<em><TD><a href=%s>%s</a>' % ('update.txt',
            'log'))
    f.write('<TR><TD><em>Graphing Log<em><TD><a href=%s>%s</a>' % ('graph.txt',
            'log'))
    f.write('<TR><TD><em>Connection Log<em><TD><a href=%s>%s</a>' % ('ssh.txt',
            'log'))
    f.write('</table>')
    f.write('<H1>%s Testbed</H1>' % TB.testbed)
    f.write('<H2>System Monitor</H2>')
    f.write('<BR><BR>')
    f.write('<HR>')
    f.write('<table>')
    f.write('<CAPTION><EM>%s</EM></CAPTION>' % TB.caption)
    f.write('<TR><TH>Hostname<TH>Status<TH>Labels<TH>Last Update')
    f.write('<TH>Release<TH>Health</TR>')
    for h in sorted_hosts:
      if TB.hosts[h.hostname]['status']:
        status = 'Ready'
        bgcolor = '#FFFFFF'
      else:
        status = 'Down'
        bgcolor = '#FF9999'
      link_dir = 'hosts/' + h.hostname + '/rrd'
      rrd_dir = os.path.join(TB.home, 'hosts', h.hostname, 'rrd')
      hlink = os.path.join(link_dir, 'hwinfo.html')
      if not os.path.isdir(rrd_dir):
        os.makedirs(rrd_dir)
        os.chmod(rrd_dir, 0755)
      f.write('<tr bgcolor=%s><th>' % bgcolor)
      f.write('<a href="%s">%s</a></th>' % (hlink, h.hostname))
      f.write('<td><em>%s</em>' % status)
      f.write('<td>')
      for label in h.labels:
        if 'netbook' in label:
          f.write('<em><b>%s</b></em><br>' % label)
        else:
          f.write('%s<br>' % label)
      f.write('<td>%s' % TB.hosts[h.hostname]['time'])
      if TB.hosts[h.hostname]['release']['PTR']:
        f.write('<td>%s' % TB.hosts[h.hostname]['release']['PTR'])
      else:
        f.write('<td>Unknown')
      index_file = os.path.join(rrd_dir, 'index.html')
      if os.path.isfile(index_file):
        f.write('<td><a href=%s' % TB.url)
        f.write('%s/index.html target="_blank">' % link_dir)
        f.write('health</a></td>')
      else:
        f.write('<td>None</td>')
    f.write('</table><p>\n</center>\n</BODY></HTML>')
    f.close()
    shutil.copyfile(LandPageTemp, LandPageFile)
    os.chmod(LandPageFile, 0644)


class Resource(object):
  """Contains structures and methods to collect health data on hosts.
  For each resource in self.resources, there must also be a corresponding
  method to format the data into what RRDTool expects.

  Args:
    filesystems: dictionary of file system devices with mountpoints.
    net_devices: list of network devices.
  """

  def __init__(self, filesystems, net_devices):
    self.files = {
      'cpu': '/proc/stat',
      'load': '/proc/loadavg',
      'memory': '/proc/meminfo',
      'power': '/proc/acpi/processor/CPU0/throttling',
      'temp': '/proc/acpi/thermal_zone/*/temperature',
      'uptime': '/proc/uptime',
      }
    # self.net_devices used when running ParseNetDev().
    self.net_dev = net_devices
    fs_specs = ['_space', '_inode', '_stats']

    ### self.fs get populated from df output.
    self.fs = {}
    for k in filesystems:
      fs_dev = os.path.basename(k)  # Strip any device directories.
      for spec in fs_specs:
        key = fs_dev + spec
        if spec == '_stats':
          self.fs[key] = fs_dev
        else:
          self.fs[key] = filesystems[k]

    self.resources = []
    for k in self.files:
      self.resources.append(k)
    for k in self.fs:
      self.resources.append(k)
    for k in self.net_dev:
      self.resources.append(k)


  def FormatData(self, hostname):
    """Convert collected data into the correct format for RRDTool.

    Args:
      hostname: string, hostname of AutoTest host.
    """

    ParseMethod = {
                   'battery': self.ParseBattery,
                   'boot': self.ParseBoot,
                   'fs': self.ParseFS,
                   'diskstats': self.ParseDiskStats,
                   'cpu': self.ParseStat,
                   'load': self.ParseLoadAvg,
                   'memory': self.ParseMemInfo,
                   'network': self.ParseNetDev,
                   'power': self.ParsePower,
                   'temp': self.ParseTemp,
                   'uptime': self.ParseUpTime,
                  }

    # method_key is used here because multiple resource keys will use the
    # same method to parse them.
    for key in TB.hosts[hostname]['data']:
      method_key = key
      if key in self.fs:
        if '_space' in key:
          method_key = 'fs'
        elif '_inode' in key:
          method_key = 'fs'
        elif '_stats' in key:
          method_key = 'diskstats'
        else:
          TB.logger.error('Error in key name of %s', key)
      if key in self.net_dev:
        method_key = 'network'
      if method_key in ParseMethod:
        if len(TB.hosts[hostname]['data'][key]) > 0:
          TB.logger.debug('Parsing %s on %s', key, hostname)
          ParseMethod[method_key](hostname, key)
      else:
        TB.logger.error('No method to parse resource %s', key)


  def ProcessRRD(self, hostname):
    """Process formatted data into RRD files.

    Args:
      hostname: string, hostname or ip address.
    """
    hostdir = os.path.join(TB.home, 'hosts', hostname)
    rrd_dir = os.path.join(hostdir, 'rrd')
    if not os.path.exists(rrd_dir):
      os.makedirs(rrd_dir)
      os.chmod(rrd_dir, 0755)
    os.chmod(hostdir, 0755)
    for r in TB.hosts[hostname]['rrddata']:
      dk = None  # set datakey if it's a file system or network device.
      if r in self.fs:
        if '_space' in r:
          dk = 'fs_space'
        elif '_inode' in r:
          dk = 'fs_inode'
        elif '_stat' in r:
          dk = 'fs_stat'
      if r in self.net_dev:
        dk = 'network'

      rrd = RRD(r, hostname, rrd_dir, datakey=dk)
      if not os.path.exists(rrd.rrdfile):
        rrd.Create()
      if TB.update == True:
        TB.logger.debug('Updating %s for host %s', r, hostname)
        if len(TB.hosts[hostname]['rrddata'][r]) > 0:
          rrd.Update()
      if TB.graph:
        TB.logger.debug('Building %s graphs for %s', r, hostname)
        rrd.Graph()


  def BuildHTML(self, hostname):
    """Create HTML pages for to display the graphs.

    Args:
      hostname: string, host of AutoTest host.
    """
    mainindex = TB.url + 'index.html'
    rrd_dir = os.path.join(TB.home, 'hosts', hostname, 'rrd')
    resource_list = []
    for r in self.resources:
      resource_list.append(r)
    resource_list.sort()
    index_file = os.path.join(rrd_dir, 'index.html')
    html_file = {}
    for t in TB.rrdtimes:
      html_file[t] = hostname + t + '.html'
    pathname = {}
    for name in html_file:
      pathname[name] = os.path.join(rrd_dir, html_file[name])

    # Create HTML files for each time period we are graphing.
    for path in pathname:
      f = open(pathname[path], 'w')
      f.write('<HTML><HEAD>')
      f.write('<center><TITLE>%s System Health</TITLE></HEAD>' % hostname)
      f.write('<BODY><H1>%s System Health</H1>' % hostname)
      for v in TB.version:
        f.write('<H4>%s: %s</H4>' % (v, TB.hosts[hostname][v]['PTR']))
      for t in TB.rrdtimes:
        f.write('<a href="%s">%s</a>&nbsp;<b>|</b>' % (html_file[t], t))
      f.write('<a href="%s">SystemHealth Home</a>' % mainindex)
      f.write('<p><HR>')

      f.write('<b>%s</b><table border=1 bgcolor=#EEEEEE>' % path)
      newrow = True
      for r in resource_list:
        if newrow:
          f.write('<tr>')
        f.write('<td>%s<br><a href=%s.html>' % (r, r))
        f.write('<img src=%s%s.png width=475 height=250></a></td>' % (r, path))
        if newrow:
          newrow = False
        else:
          f.write('</tr>\n')
          newrow = True
      f.write('</table><p>\n')
      f.write('</center>\n')
      f.write('<H5>Last Update: %s</H5>' % TB.hosts[hostname]['time'])
      f.write('</BODY></HTML>')
      f.close()
      os.chmod(pathname[path], 0644)
    if not os.path.isfile(index_file):
      os.symlink(pathname[TB.rrdtimes[0]], index_file)

    # Create HTML files for each resource for all time periods.
    for r in resource_list:
      rrdfile = os.path.join(rrd_dir, r + '.html')
      f = open(rrdfile, 'w')
      f.write('<HTML><HEAD>')
      f.write('<center><TITLE>%s %s Resources</TITLE></HEAD>' % (hostname, r))
      f.write('<BODY><H1>%s %s Resources</H1>' % (hostname, r))
      for v in TB.version:
        f.write('<H4>%s: %s</H4>' % (v, TB.hosts[hostname][v]['PTR']))
      f.write('<table border=5 bgcolor=#B5B5B5>')
      f.write('<tr>')
      for t in TB.rrdtimes:
        f.write('<td><a href="#%s"><b>%s</b></a>' % (t, t))
      f.write('</table>')
      f.write('<HR>')
      f.write('<table border=1 bgcolor=#EEEEEE>')
      for t in TB.rrdtimes:
        f.write('<tr><td><a name="%s"><img src=%s%s.png>' % (t, r, t))
        f.write('</a></td></tr>\n')
      f.write('</table><p>\n')
      f.write('</center>\n')
      f.write('<H5>Last Update: %s</H5>' % TB.hosts[hostname]['time'])
      f.write('</BODY></HTML>')
      f.close()
      os.chmod(rrdfile, 0644)


  def ParseBattery(self, h, k):
    """Convert /proc/acpi/battery/BAT0/state to a list of strings.

    Args:
      h: string, hostname of host in AutoTest.
      k: string, resource key.
    We only care about the values corresponding to the rrdkeys, so the other
    values will be discarded.
    """
    rrdkeys = ['charging state', 'present rate', 'remaining capacity',]
    TB.hosts[h]['rrddata'][k] = []
    statlist = TB.hosts[h]['data'][k].split('\n')
    for stat in statlist:
      for key in rrdkeys:
        if key in stat:
          stats = stat.split(':')
          temp = stats[1].split()
          if key == 'charging state':
            if temp[0] == 'discharging':
              TB.hosts[h]['rrddata'][k].append('0')
            else:
              TB.hosts[h]['rrddata'][k].append('1')
          else:
            TB.hosts[h]['rrddata'][k].append(temp[0])


  def ParseBoot(self, h, k):
    """Parse /tmp/uptime-login-prompt-ready for boot time.

    Args:
      h: string, hostname of host in AutoTest.
      k: string, resource key.
    We only want the first and 2nd values from the raw data.
    """
    fields = []
    TB.hosts[h]['rrddata'][k] = []
    lines = TB.hosts[h]['data'][k].split('\n')
    for line in lines:
      fields.extend(line.split())
    TB.hosts[h]['rrddata'][k] = fields[0:2]


  def ParseFS(self, h, k):
    """Convert file system space and inode readings to a list of strings.

    Args:
      h: string, hostname of host in AutoTest.
      k: string, resource key.
    """
    TB.hosts[h]['rrddata'][k] = []
    lines = TB.hosts[h]['data'][k].split('\n')
    for line in lines:
      if not line.startswith('Filesystem'):
        fields = line.split()
        if len(fields) > 4:
          TB.hosts[h]['rrddata'][k].append(fields[2])
          TB.hosts[h]['rrddata'][k].append(fields[3])


  def ParseDiskStats(self, h, k):
    """Parse read and write sectors from /proc/diskstats to list of strings.

    Args:
      h: string, hostname of host in AutoTest.
      k: string, resource key.
    """
    TB.hosts[h]['rrddata'][k] = []
    fields = TB.hosts[h]['data'][k].split()
    if len(fields) > 9:
      TB.hosts[h]['rrddata'][k].append(fields[5])
      TB.hosts[h]['rrddata'][k].append(fields[9])


  def ParseStat(self, h, k):
    """Convert /proc/stat to lists for CPU usage.

    Args:
      h: string, hostname of host in AutoTest.
      k: string, resource key.
    """
    lines = TB.hosts[h]['data'][k].split('\n')
    for line in lines:
      if 'cpu ' in line:
        vals = line.split()
        TB.hosts[h]['rrddata'][k] = vals[1:5]


  def ParseLoadAvg(self, h, k):
    """Convert /proc/loadavg to a list of strings to monitor.

    Args:
      h: string, hostname of host in AutoTest.
      k: string, resource key.
    Process ID is discarded, as it's not needed.
    """
    statlist = TB.hosts[h]['data'][k].split()
    TB.hosts[h]['rrddata'][k] = statlist[0:3]


  def ParseMemInfo(self, h, k):
    """Convert specified fields in /proc/meminfo to a list of strings.

    Args:
      h: string, hostname of host in AutoTest.
      k: string, resoruce key.
    """
    TB.hosts[h]['rrddata'][k] = []
    mem_keys = ['MemTotal', 'MemFree', 'Buffers', 'Cached', 'SwapTotal',
                'SwapFree']
    lines = TB.hosts[h]['data'][k].split('\n')
    for line in lines:
      for key in mem_keys:
        if key in line:
          if not 'SwapCached' in line:
            fields = line.split()
            TB.hosts[h]['rrddata'][k].append(fields[1])


  def ParseNetDev(self, h, k):
    """Convert /proc/net/dev to a list of strings of rec and xmit values.

    Args:
      h: string, hostname of host in AutoTest.
      k: string, resource key.
    """
    rrdlist = ['0', '0']
    lines = TB.hosts[h]['data'][k].split('\n')
    for line in lines:
      if k in line:
        (device, data) = line.split(':')
        fields = data.split()
        rrdlist[0] = fields[0]
        rrdlist[1] = fields[8]

    TB.hosts[h]['rrddata'][k] = rrdlist


  def ParsePower(self, h, k):
    """Convert /proc/acpi/processor/CPU0/throttling to power percentage.

    Args:
      h: string, hostname of host in AutoTest.
      k: string, resource key.
    """
    fields = None
    TB.hosts[h]['rrddata'][k] = []
    lines = TB.hosts[h]['data'][k].split('\n')
    for line in lines:
      line = line.strip()
      if line.startswith('*'):
        fields = line.split(':')

    if fields:
      if len(fields) > 1:
        percent = fields[1].strip('%')
        percent = percent.strip()
        TB.hosts[h]['rrddata'][k].append(percent)


  def ParseTemp(self, h, k):
    """Convert temperature readings to a list of strings.

    Args:
      h: string, hostname of host in AutoTest.
      k: string, resource key.
    """
    TB.hosts[h]['rrddata'][k] = []
    statlist = TB.hosts[h]['data'][k].split()
    if len(statlist) > 1:
      TB.hosts[h]['rrddata'][k].append(statlist[1])


  def ParseUpTime(self, h, k):
    """Convert /proc/uptime to a list of strings.

    Args:
      h: string, hostname of host in AutoTest.
      k: string, resource key.
    """

    TB.hosts[h]['rrddata'][k] = TB.hosts[h]['data'][k].split()


  def GetCommands(self):
    """Routine for gathering data from files and file systems.
    Returns:
      dictionary of commands to run on hosts.
    """

    command = {}

    for r in self.resources:
      if r in self.files:
        command[r] = 'cat %s' % self.files[r]
      elif r in self.net_dev:
        command[r] = 'cat /proc/net/dev | grep %s' % r
      elif r in self.fs:
        if '_space' in r:
          command[r] = 'df -lP %s' % self.fs[r]
        elif '_inode' in r:
          command[r] = 'df -iP %s' % self.fs[r]
        elif '_stat' in r:
          command[r] = 'cat /proc/diskstats | grep %s' % self.fs[r]
        else:
          TB.logger.error('Error in key name of %s', r)
    return command


class RRD(object):
  """The class to create and update RRD data stores and graph them.

  This class should be used to access all of the functions of RRDTool. It will
  create the data files, update them, and create graphs/charts based on that
  data. Datakey is needed when we are using the same data definitions for many
  items of the same type, like file systems.
  """
  def __init__(self, rrdname, hostname, rrd_dir, datakey=None):
    """
    Args:
      rrdname: string, item name(should match key from Resources)
      hostname: string, hostname of the machine.
      rrd_dir: string, directory for all rrd files and graphs.
      datakey: string, overrides which data definition to use.
    """
    self.rrdtool = '/usr/bin/rrdtool'
    self.rrd_dir = rrd_dir
    if not os.path.exists(self.rrd_dir):
      try:
        os.makedirs(self.rrd_dir)
        os.chmod(self.rrd_dir, 0755)
      except OSError:
        TB.logger.error('Error creating %s', self.rrd_dir)
    self.rrdname = rrdname
    self.hostname = hostname
    rrd_filename = rrdname + '.rrd'
    self.rrdfile = os.path.join(self.rrd_dir, rrd_filename)
    file_system = 'Unknown'

    if not datakey:
      datakey = rrdname
    elif datakey != 'network':
      fields = rrdname.split('_')
      if len(fields[0]) > 0:
        file_system = fields[0]

    data_def = {
      'battery': {
        'heartbeat': '600',
        'min': '0',
        'max': 'U',
        'title': '"%s Battery Status' % self.hostname,
        'type': 'GAUGE',
        'units': '"Mili Amps"',
        'items': [
                  'State',
                  'Rate',
                  'Capacity',
                 ],
        'graph': [
                  '-l 0 -r',
                  'CDEF:bat=State,1,LT,50,UNKN,IF',
                  'CDEF:ac=State,1,LT,UNKN,50,IF',
                  'CDEF:RateD=State,1,LT,Rate,UNKN,IF',
                  'CDEF:RateC=State,1,LT,UNKN,Rate,IF',
                  'CDEF:bg=Capacity,UN,0,Capacity,IF,0,GT,INF,UNKN,IF',
                  'AREA:bg#DDDDDD:',
                  'AREA:Capacity#99CCFF:"Capacity      "',
                  'LINE1:Capacity#3399FF:',
                  'VDEF:max1=Capacity,MAXIMUM',
                  'VDEF:min1=Capacity,MINIMUM',
                  'VDEF:avg1=Capacity,AVERAGE',
                  'GPRINT:max1:"Max %6.3lf%s"',
                  'GPRINT:min1:"Min %6.3lf%s"',
                  'GPRINT:avg1:" Avg %6.3lf%s"',
                  'AREA:bat#CC0000:"Battery \\n"',
                  'LINE2:RateD#990033:"Discharge Rate"',
                  'VDEF:max2=RateD,MAXIMUM',
                  'VDEF:min2=RateD,MINIMUM',
                  'VDEF:avg2=RateD,AVERAGE',
                  'GPRINT:max2:"Max %6.3lf%s"',
                  'GPRINT:min2:"Min %6.3lf%s"',
                  'GPRINT:avg2:"Avg %6.3lf%s"',
                  'AREA:ac#33FF66:"AC Connected \\n"',
                  'LINE2:RateC#009966:"Charge Rate   "',
                  'VDEF:max3=RateC,MAXIMUM',
                  'VDEF:min3=RateC,MINIMUM',
                  'VDEF:avg3=RateC,AVERAGE',
                  'GPRINT:max3:"Max %6.3lf%s"',
                  'GPRINT:min3:"Min %6.3lf%s"',
                  'GPRINT:avg3:" Avg %6.3lf%s\\n"',
                 ],
        },
      'boot': {
        'heartbeat': '600',
        'min': '0',
        'max': 'U',
        'title': '"%s Boot time to Login Prompt' % self.hostname,
        'type': 'GAUGE',
        'units': '"Seconds"',
        'items': [
                  'firmware',
                  'ready',
                 ],
        'graph': [
                  '-l 0 -u 30 -r',
                  'CDEF:total=firmware,ready,+',
                  'CDEF:bg=total,UN,0,total,IF,0,GT,UNKN,INF,IF',
                  'AREA:bg#DDDDDD:',
                  'AREA:firmware#26466D:"Firmware    "',
                  'LINE1:firmware#660000:',
                  'VDEF:maxF=firmware,MAXIMUM',
                  'VDEF:minF=firmware,MINIMUM',
                  'VDEF:avgF=firmware,AVERAGE',
                  'GPRINT:minF:"Min %2.1lf"',
                  'GPRINT:maxF:"Max %2.1lf"',
                  'GPRINT:avgF:"Avg %2.1lf Seconds \\n"',
                  'AREA:ready#0BB5FF:"Login Prompt":STACK',
                  'LINE1:firmware#660000:',
                  'VDEF:maxR=ready,MAXIMUM',
                  'VDEF:minR=ready,MINIMUM',
                  'VDEF:avgR=ready,AVERAGE',
                  'GPRINT:minR:"Min %2.1lf"',
                  'GPRINT:maxR:"Max %2.1lf"',
                  'GPRINT:avgR:"Avg %2.1lf Seconds \\n"',
                  'VDEF:maxT=total,MAXIMUM',
                  'VDEF:minT=total,MINIMUM',
                  'VDEF:avgT=total,AVERAGE',
                  'GPRINT:minT:"Total           Min %2.1lf"',
                  'GPRINT:maxT:"Max %2.1lf"',
                  'GPRINT:avgT:"Avg %2.1lf Seconds \\n"',
                  'HRULE:15#FF0000',
                  'HRULE:10#FFA500',
                 ],
        },
      'cpu': {
        'heartbeat': '600',
        'min': '0',
        'max': 'U',
        'title': '"%s CPU Usage' % self.hostname,
        'type': 'DERIVE',
        'units': 'jiffies',
        'items': [
                  'user',
                  'nice',
                  'system',
                  'idle',
                 ],
        'graph': [
                  '-l 0 -r -u 99.99',
                  'CDEF:l=user,0.1,0.1,IF',
                  'CDEF:bg=user,UN,0,user,IF,0,GT,UNKN,INF,IF',
                  'AREA:bg#DDDDDD:',
                  'CDEF:tj=user,nice,+,system,+,idle,+',
                  'CDEF:usr=100,user,*,tj,/',
                  'CDEF:nic=100,nice,*,tj,/',
                  'CDEF:sys=100,system,*,tj,/',
                  'CDEF:idl=100,idle,*,tj,/',
                  'CDEF:tot=100,tj,*,tj,/',
                  'AREA:nic#0040A2:"Nice  "',
                  'VDEF:maxN=nic,MAXIMUM',
                  'VDEF:minN=nic,MINIMUM',
                  'VDEF:avgN=nic,AVERAGE',
                  'GPRINT:maxN:"Max %6.2lf%s"',
                  'GPRINT:minN:"Min %6.2lf%s"',
                  'GPRINT:avgN:"Avg %6.2lf%s \\n"',
                  'AREA:sys#3399FF:System:STACK',
                  'LINE2:l#70A5AC::STACK',
                  'VDEF:maxS=sys,MAXIMUM',
                  'VDEF:minS=sys,MINIMUM',
                  'VDEF:avgS=sys,AVERAGE',
                  'GPRINT:maxS:"Max %6.2lf%s"',
                  'GPRINT:minS:"Min %6.2lf%s"',
                  'GPRINT:avgS:"Avg %6.2lf%s \\n"',
                  'AREA:usr#B0F5EC:"User  ":STACK',
                  'LINE2:l#90C5CC::STACK',
                  'VDEF:maxU=usr,MAXIMUM',
                  'VDEF:minU=usr,MINIMUM',
                  'VDEF:avgU=usr,AVERAGE',
                  'GPRINT:maxU:"Max %6.2lf%s"',
                  'GPRINT:minU:"Min %6.2lf%s"',
                  'GPRINT:avgU:"Avg %6.2lf%s \\n"',
                  'AREA:idl#EEFFFF:"Idle  ":STACK',
                  'VDEF:maxI=idl,MAXIMUM',
                  'VDEF:minI=idl,MINIMUM',
                  'VDEF:avgI=idl,AVERAGE',
                  'GPRINT:maxI:"Max %6.2lf%s"',
                  'GPRINT:minI:"Min %6.2lf%s"',
                  'GPRINT:avgI:"Avg %6.2lf%s \\n"',
                 ],
        },
      'fs_inode': {
        'heartbeat': '600',
        'min': '0',
        'max': 'U',
        'title': '"%s %s File System Inodes' % (self.hostname, file_system),
        'type': 'GAUGE',
        'units': 'Quantity',
        'items': [
                  'Used',
                  'Free',
                 ],
        'graph': [
                  '-l 0 -r',
                  'CDEF:bg=Used,UN,0,Used,IF,0,GT,UNKN,INF,IF',
                  'AREA:bg#DDDDDD',
                  'CDEF:inodes=Used,Free,+',
                  'VDEF:inodesTotal=inodes,LAST',
                  'GPRINT:inodesTotal:"Total   %6.2lf %s\\n"',
                  'AREA:Used#000066:"Used"',
                  'VDEF:usedLast=Used,LAST',
                  'GPRINT:usedLast:"%6.2lf %s"',
                  'CDEF:usedPct=Used,100,*,inodes,/',
                  'VDEF:pctUsed=usedPct,LAST',
                  'GPRINT:pctUsed:"%6.2lf%%\\n"',
                  'AREA:Free#3399FF:"Free":STACK',
                  'VDEF:freeLast=Free,LAST',
                  'GPRINT:freeLast:"%6.2lf %s"',
                  'CDEF:freePct=100,usedPct,-',
                  'VDEF:pctFree=freePct,LAST',
                  'GPRINT:pctFree:"%6.2lf%%\\n"',
                 ],
        },
      'fs_space': {
        'heartbeat': '600',
        'min': '0',
        'max': 'U',
        'title': '"%s %s File System Space' % (self.hostname, file_system),
        'type': 'GAUGE',
        'units': 'Bytes',
        'items': [
                  'Used',
                  'Free',
                 ],
        'graph': [
                  '-l 0 -r',
                  'CDEF:bg=Used,UN,0,Used,IF,0,GT,UNKN,INF,IF',
                  'AREA:bg#DDDDDD',
                  'CDEF:UsedB=Used,1024,*',
                  'CDEF:FreeB=Free,1024,*',
                  'CDEF:fs=UsedB,FreeB,+',
                  'VDEF:fsTotal=fs,LAST',
                  'GPRINT:fsTotal:"Total   %6.2lf %sB\\n"',
                  'AREA:UsedB#003399:"Used"',
                  'VDEF:usedLast=UsedB,LAST',
                  'GPRINT:usedLast:"%6.2lf %sB"',
                  'CDEF:usedPct=UsedB,100,*,fs,/',
                  'VDEF:pctUsed=usedPct,LAST',
                  'GPRINT:pctUsed:"%6.2lf%%\\n"',
                  'AREA:FreeB#6699CC:"Free":STACK',
                  'VDEF:freeLast=FreeB,LAST',
                  'GPRINT:freeLast:"%6.2lf %sB"',
                  'CDEF:freePct=100,usedPct,-',
                  'VDEF:pctFree=freePct,LAST',
                  'GPRINT:pctFree:"%6.2lf%%\\n"',
                 ],
        },
      'fs_stat': {
        'heartbeat': '600',
        'min': 'U',
        'max': 'U',
        'title': '"%s %s File System Activity' % (self.hostname, file_system),
        'type': 'DERIVE',
        'units': '"Bytes"',
        'items': [
                  'Reads',
                  'Writes',
                 ],
        'graph': [
                  '-r',
                  'CDEF:bWrites=Writes,-512,*',
                  'CDEF:bReads=Reads,512,*',
                  'AREA:bWrites#990000:"Bytes Written\\n"',
                  'AREA:bReads#0066CC:"Bytes Read"',
                  'HRULE:0#000000',
                  ],
        },
      'load': {
        'heartbeat': '600',
        'min': '0',
        'max': '100',
        'title': '"%s Load Levels' % self.hostname,
        'type': 'GAUGE',
        'units': 'proc/min',
        'items': [
                  'load_1',
                  'load_5',
                  'load_15',
                 ],
        'graph': [
                  '-r',
                  'CDEF:bg=load_1,UN,0,load_1,IF,0,GT,UNKN,INF,IF',
                  'AREA:bg#DDDDDD:',
                  'CDEF:bi=load_1,UN,0,load_1,IF,0,GT,INF,UNKN,IF',
                  'AREA:bi#FEFEED:',
                  'HRULE:1.0#44B5FF',
                  'AREA:load_15#99FFCC:"Last 15 min"',
                  'VDEF:max3=load_15,MAXIMUM',
                  'VDEF:min3=load_15,MINIMUM',
                  'VDEF:avg3=load_15,AVERAGE',
                  'GPRINT:max3:"Max %6.2lf"',
                  'GPRINT:min3:"Min %6.2lf"',
                  'GPRINT:avg3:"Avg %6.2lf\\n"',
                  'LINE2:load_5#3399FF:"Last 5 min "',
                  'VDEF:max2=load_5,MAXIMUM',
                  'VDEF:min2=load_5,MINIMUM',
                  'VDEF:avg2=load_5,AVERAGE',
                  'GPRINT:max2:"Max %6.2lf"',
                  'GPRINT:min2:"Min %6.2lf"',
                  'GPRINT:avg2:"Avg %6.2lf\\n"',
                  'LINE2:load_1#993366:"Last 1 min "',
                  'VDEF:max1=load_1,MAXIMUM',
                  'VDEF:min1=load_1,MINIMUM',
                  'VDEF:avg1=load_1,AVERAGE',
                  'GPRINT:max1:"Max %6.2lf"',
                  'GPRINT:min1:"Min %6.2lf"',
                  'GPRINT:avg1:"Avg %6.2lf\\n"',
                 ],
        },
      'memory': {
        'heartbeat': '600',
        'min': '0',
        'max': '10000000',
        'title': '"%s Memory Usage' % self.hostname,
        'type': 'GAUGE',
        'units': 'bytes',
        'items': [
                  'MemTotal',
                  'MemFree',
                  'Buffers',
                  'Cached',
                  'SwapTotal',
                  'SwapFree',
                 ],
        'graph': [
                  '-r',
                  'CDEF:bg=MemTotal,UN,0,MemTotal,IF,0,GT,UNKN,INF,IF',
                  'AREA:bg#DDDDDD:',
                  'CDEF:sum=MemTotal,1024,*',
                  'CDEF:free=MemFree,1024,*',
                  'CDEF:buff=Buffers,1024,*',
                  'CDEF:buffP=buff,100,*,sum,/',
                  'CDEF:cache=Cached,1024,*',
                  'CDEF:user=MemTotal,MemFree,Cached,+,Buffers,+,-,1024,*',
                  'CDEF:l=user,1,1,IF',
                  'AREA:user#003366:"User    "',
                  'LINE2:l#AC1300::STACK',
                  'VDEF:maxUser=user,MAXIMUM',
                  'VDEF:minUser=user,MINIMUM',
                  'VDEF:avgUser=user,AVERAGE',
                  'VDEF:curUser=user,LAST',
                  'GPRINT:curUser:"Last %6.2lf %s"',
                  'GPRINT:avgUser:"Avg %6.2lf %s"',
                  'GPRINT:maxUser:"Max %6.2lf %s"',
                  'GPRINT:minUser:"Min %6.2lf %s\\n"',
                  'AREA:cache#336699:"Cached  ":STACK',
                  'LINE2:l#DF7900::STACK',
                  'VDEF:maxCache=cache,MAXIMUM',
                  'VDEF:minCache=cache,MINIMUM',
                  'VDEF:avgCache=cache,AVERAGE',
                  'VDEF:curCache=cache,LAST',
                  'GPRINT:curCache:"Last %6.2lf %s"',
                  'GPRINT:avgCache:"Avg %6.2lf %s"',
                  'GPRINT:maxCache:"Max %6.2lf %s"',
                  'GPRINT:minCache:"Min %6.2lf %s\\n"',
                  'AREA:buff#99CCFF:"Buffers":STACK',
                  'LINE2:l#DFAC00::STACK',
                  'VDEF:maxBuff=buff,MAXIMUM',
                  'VDEF:minBuff=buff,MINIMUM',
                  'VDEF:avgBuff=buff,AVERAGE',
                  'VDEF:curBuff=buff,LAST',
                  'GPRINT:curBuff:"Last %6.2lf %s"',
                  'GPRINT:avgBuff:"Avg %6.2lf %s"',
                  'GPRINT:maxBuff:"Max %6.2lf %s"',
                  'GPRINT:minBuff:"Min %6.2lf %s\\n"',
                  'AREA:free#CCFFCC:"Unused ":STACK',
                  'VDEF:maxFree=free,MAXIMUM',
                  'VDEF:minFree=free,MINIMUM',
                  'VDEF:avgFree=free,AVERAGE',
                  'VDEF:curFree=free,LAST',
                  'GPRINT:curFree:"Last %6.2lf %s"',
                  'GPRINT:avgFree:"Avg %6.2lf %s"',
                  'GPRINT:maxFree:"Max %6.2lf %s"',
                  'GPRINT:minFree:"Min %6.2lf %s\\n"',
                 ],
        },
      'network': {
        'heartbeat': '600',
        'min': '0',
        'max': '12500000',
        'title': '"%s %s Network Traffic' % (self.rrdname, self.hostname),
        'type': 'DERIVE',
        'units': 'bytes/s',
        'items': [
                  'recd',
                  'sent',
                 ],
        'graph': [
                  '-r',
                  'VDEF:max1=recd,MAXIMUM',
                  'CDEF:eoff=recd,UN,0,recd,IF,0,GT,UNKN,0,IF',
                  'CDEF:eon=0,recd,UN,0,recd,IF,0,GT,max1,50,/,UNKN,IF,-',
                  'CDEF:bi=recd,UN,0,recd,IF,0,GT,INF,UNKN,IF',
                  'CDEF:bg=recd,UN,0,recd,IF,0,GT,UNKN,INF,IF',
                  'AREA:bi#DDDDDD:',
                  'AREA:recd#000066:"Received "',
                  'LINE1:recd#0000CC:',
                  'VDEF:min1=recd,MINIMUM',
                  'VDEF:avg1=recd,AVERAGE',
                  'VDEF:tot1=recd,TOTAL',
                  'GPRINT:max1:"Max %6.2lf%s"',
                  'GPRINT:min1:"Min %6.2lf%s"',
                  'GPRINT:avg1:"Avg %6.2lf%s"',
                  'GPRINT:tot1:"Sum %6.2lf%s\\n"',
                  'CDEF:xmit=sent,-1,*',
                  'AREA:xmit#990033:"Transmitted"',
                  'VDEF:max2=xmit,MAXIMUM',
                  'VDEF:min2=xmit,MINIMUM',
                  'VDEF:avg2=xmit,AVERAGE',
                  'VDEF:tot2=xmit,TOTAL',
                  'GPRINT:max2:"Max %6.2lf%s"',
                  'GPRINT:min2:"Min %6.2lf%s"',
                  'GPRINT:avg2:"Avg %6.2lf%s"',
                  'GPRINT:tot2:"Sum %6.2lf%s\\n"',
                  'AREA:bg#DDDDDD:',
                  'LINE3:eoff#000000:"Offline \\n"',
                  'LINE3:eon#00CC66:"Online \\n"',
                 ],
        },
      'power': {
        'heartbeat': '600',
        'min': '0',
        'max': '100',
        'title': '"%s Power State' % self.hostname,
        'type': 'GAUGE',
        'units': 'Percentage',
        'items': ['state',],
        'graph': [
                  '-l 0 -r',
                  'CDEF:bg=state,UN,0,state,IF,0,GT,UNKN,INF,IF',
                  'AREA:bg#DDDDDD:',
                  'VDEF:pstate=state,LAST',
                  'AREA:pstate#CC3333:"Power Setting "',
                  'VDEF:pstateMax=state,MAXIMUM',
                  'VDEF:pstateMin=state,MINIMUM',
                  'VDEF:pstateAvg=state,AVERAGE',
                  'GPRINT:pstateMax:"Max %6.2lf%s%%"',
                  'GPRINT:pstateMin:"Min %6.2lf%s%%"',
                  'GPRINT:pstateAvg:"Avg %6.2lf%s%%\\n"',
                 ],
        },
      'temp': {
        'heartbeat': '600',
        'min': '0',
        'max': '100',
        'title': '"%s Temperature Readings' % self.hostname,
        'type': 'GAUGE',
        'units': 'Celsius',
        'items': [
                  'cpu',
                 ],
        'graph': [
                  '-l 20 -r',
                  'CDEF:bg=cpu,UN,0,cpu,IF,0,GT,UNKN,INF,IF',
                  'AREA:bg#DDDDDD:',
                  'CDEF:cool=cpu,40,LE,cpu,UNKN,IF',
                  'CDEF:warm=cpu,40,60,LIMIT',
                  'CDEF:hot=cpu,60,GE,cpu,UNKN,IF',
                  'AREA:cool#B0F5EC:"Cool "',
                  'AREA:warm#FFCC00:"Warm "',
                  'AREA:hot#CC3300:"Hot  \\n"',
                  'VDEF:maxC=cpu,MAXIMUM',
                  'VDEF:minC=cpu,MINIMUM',
                  'VDEF:avgC=cpu,AVERAGE',
                  'GPRINT:minC:"Min %2.1lf"',
                  'GPRINT:maxC:"Max %2.1lf"',
                  'GPRINT:avgC:"Avg %2.1lf Celsius \\n"',
                  'LINE1:cpu#660000:',
                  'HRULE:60#FF0000',
                  'HRULE:20#FFA500',
                 ],
        },
      'uptime': {
        'heartbeat': '600',
        'min': '0',
        'max': 'U',
        'title': '"%s Uptime Readings' % self.hostname,
        'type': 'GAUGE',
        'units': 'hours',
        'items': [
                  'uptime',
                  'idletime',
                 ],
        'graph': [
                  '-r',
                  'CDEF:bg=uptime,UN,0,uptime,IF,0,GT,UNKN,INF,IF',
                  'AREA:bg#DDDDDD:',
                  'CDEF:upHours=uptime,3600,/',
                  'CDEF:idleHours=idletime,3600,/',
                  'AREA:upHours#99CC99:"Uptime  "',
                  'GPRINT:upHours:MIN:"Min %8.2lf"',
                  'GPRINT:upHours:MAX:"Max %8.2lf"',
                  'GPRINT:upHours:AVERAGE:"Avg %8.2lf"',
                  'GPRINT:upHours:LAST:"Last %8.2lf\\n"',
                  'LINE2:idleHours#333333:"Idletime"',
                  'GPRINT:idleHours:MIN:"Min %8.2lf"',
                  'GPRINT:idleHours:MAX:"Max %8.2lf"',
                  'GPRINT:idleHours:AVERAGE:"Avg %8.2lf"',
                  'GPRINT:idleHours:LAST:"Last %8.2lf\\n"',
                 ],
        },
      }

    self.dd = data_def[datakey]

  def Create(self):
    """Create an empty RRD file.

    Returns:
      boolean: True = Success, False = failure.
    """

    stime = int(time()) -5 * 86400
    rrd_suffix = ['RRA:AVERAGE:0.5:1:576',
                  'RRA:AVERAGE:0.5:6:672',
                  'RRA:AVERAGE:0.5:24:732',
                  'RRA:AVERAGE:0.5:144:1460',
                 ]

    rrd_cmd = [self.rrdtool, 'create', self.rrdfile, '--start', str(stime),
               '--step', '300']
    for ds in self.dd['items']:
      ds_str = 'DS:%s:%s:%s:%s:%s' % (ds, self.dd['type'],
                                          self.dd['heartbeat'],
                                          self.dd['min'],
                                          self.dd['max'])
      rrd_cmd.append(ds_str)
    rrd_cmd = rrd_cmd + rrd_suffix
    # Convert the rrd_cmd to a string with space separated commands.
    exec_str = ' '.join(rrd_cmd)
    result = self.Exec(exec_str)
    if result:
      TB.logger.error('Error executing:')
      TB.logger.error('%s\n', exec_str)

    return result


  def Update(self):
    """Update an existing RRD file.

    Returns:
      boolean: True = Success, False = errors.
    """
    if len(TB.hosts[self.hostname]['rrddata'][self.rrdname]) < 2:
      data = 'N:' + TB.hosts[self.hostname]['rrddata'][self.rrdname][0]
    else:
      data = 'N:' + ':'.join(TB.hosts[self.hostname]['rrddata'][self.rrdname])
    rrd_cmd = [self.rrdtool, 'update', self.rrdfile, data]
    exec_str = ' '.join(rrd_cmd)
    result = self.Exec(exec_str)
    if result:
      TB.logger.error('Error executing:')
      TB.logger.error('%s\n', exec_str)

    return result


  def Graph(self):
    """Create a graph of a tracked resource."""
    width = '850'
    height = '300'
    end = 'now'
    rcolor = {'release': '#9966FF',
              'bios': '#990033',
              'model': '#009933',
             }

    for time in TB.rrdtimes:
      png_filename = self.rrdname + time + '.png'
      png_file = os.path.join(self.rrd_dir, png_filename)

      title = self.dd['title'] + ' ' + time + '"'

      rrd_cmd = [self.rrdtool, 'graph', png_file, '--imgformat PNG', '-s', time,
                 '--end', end, '--width', width, '--height', height, 
                 '--vertical-label', self.dd['units'], '--title', title]

      for ds in self.dd['items']:
        rrd_cmd.append('DEF:%s=%s:%s:AVERAGE' % (ds, self.rrdfile, ds))
      rrd_cmd = rrd_cmd + self.dd['graph']
      rrd_cmd.append('COMMENT:"Release History \\s"')
      rrd_cmd.append('COMMENT:"=============== \\n"')
      for v in TB.version:
        sorted_items = []
        for k in TB.hosts[self.hostname][v]:
          if k != 'PTR':
            sorted_items.append(k)
          sorted_items.sort()
        for i in sorted_items:
          # Get a date/time string to display, localtime requires
          # a float, so convert i to float.
          datetime = strftime('%D %H\\:%M', localtime(float(i)))
          # Need to escape any ':' for RRDTool.
          filter_val = (
            TB.hosts[self.hostname][v][i].replace(':', '\\:'))
          # Insert Veritical Lines for release and firmware updates.
          vrule = 'VRULE:%s%s:"%s %s=%s \\n"' % (i, rcolor[v], datetime, v, 
                   filter_val)
          rrd_cmd.append(vrule)

      exec_str = ' '.join(rrd_cmd)
      result = self.Exec(exec_str)
      if result:
        TB.logger.error('Error while running %s', exec_str)
      if os.path.isfile(png_file):
        os.chmod(png_file, 0644)


  def Exec(self, cmd, output=False):
    """Run subprocess.Popen() and return output if output=True.

    Args:
      cmd: string, represents command with arguments.
      output: boolean, True=capture and return output.
    Returns:
      string if output = True
      return code of command if output = False
    """

    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    p.wait()
    out = p.stdout.read()
    errors = p.stderr.read()
    if p.returncode:
      TB.logger.error(out)
      TB.logger.error(errors)

    if output:
      return out
    else:
      return p.returncode


class TBQueue(Queue.Queue):
  """A subclass of class Queue to override join method with timeout."""

  def __init__(self):
    Queue.Queue.__init__(self)


  def join(self, timeout=None):
    deadline = None
    waittime = None
    if timeout:
      deadline = time() + timeout
    self.all_tasks_done.acquire()
    try:
      while self.unfinished_tasks:
        if deadline:
          waittime = deadline - time()
          if waittime < 0:
            break
        self.all_tasks_done.wait(waittime)
    finally:
      self.all_tasks_done.release()


class Host(object):
  def __init__(self, hostname, label):
    self.hostname = hostname
    self.status = 'Ready'
    self.labels = []
    self.labels.append(label)


def ParseArgs():
  """Parse all command line options."""
  private_key = '/home/kdlucas/.ssh/id_rsa'
  systemhealth_home = '/var/tmp/systemhealth'

  parser = optparse.OptionParser(version= __version__)
  parser.add_option('--conffile',
                    help='Name of configuration file [default: %default]',
                    default='watchdog.yaml',
                    dest='conffile')
  parser.add_option('--debug',
                    help='Set the debug level [default: %default]',
                    type='choice',
                    choices=['debug', 'info', 'warning', 'error', 'critical',],
                    default='info',
                    dest='debug')
  parser.add_option('--graph',
                    help='Create graphs for each host [default: %default]',
                    default=False,
                    dest='graph')
  parser.add_option('--html',
                    help='Build HTML pages for hosts [default: %default]',
                    default=False,
                    dest='html')
  parser.add_option('--logfile',
                    help='name of logfile [default: %default]',
                    default='update.log',
                    dest='logfile')
  parser.add_option('--log_to_stdout',
                    help='Send output to StdOut [default: %default]',
                    default=False,
                    dest='log_to_stdout')
  parser.add_option('--testbed',
                    help='Designate which testbed to use [default: %default]',
                    default='default',
                    dest='testbed')
  parser.add_option('--update',
                    help='Collect data from hosts [default: %default]',
                    default=True,
                    dest='update')

  return parser.parse_args()


def CheckRun(action):
  """Check the run status of watchdog.py, and add/remove run files.

  This function will ensure we only running one program with either the graph
  or update option.
  Args:
    action: string, indicates if watchdog.py is starting or stopping.
  """
  if action == 'start':
    if TB.update == True:
      if os.path.isfile(TB.update_runfile):
        TB.logger.info('Exiting, already running with update option')
        sys.exit(1)
      else:
        try:
          open(TB.update_runfile, 'w').close()
        except IOError, e:
          TB.logger.error('Error with %s\n%s', TB.update_runfile, e)
    if TB.graph:
      if os.path.isfile(TB.graph_runfile):
        TB.logger.info('Exiting, already running with graph option')
        sys.exit(1)
      else:
        try:
          open(TB.graph_runfile, 'w').close()
        except IOError, e:
          TB.logger.error('Error with %s\n%s', TB.graph_runfile, e)
  elif action == 'stop':
    if TB.update == True:
      if os.path.isfile(TB.update_runfile):
        try:
          os.remove(TB.update_runfile)
        except IOError, e:
          TB.logger.error('Error with %s\n%s', TB.update_runfile, e)
    if TB.graph:
      if os.path.isfile(TB.graph_runfile):
        try:
          os.remove(TB.graph_runfile)
        except IOError, e:
          TB.logger.error('Error with %s\n%s', TB.graph_runfile, e)
  else:
    TB.logger.error('Unknown option passed to CheckRun(): %s', action)
    sys.exit(1)


def main(argv):
  options, args = ParseArgs()

  global TB
  TB = TestBed(options.conffile, options.logfile, options.log_to_stdout,
               options.debug, options.graph, options.html, options.testbed,
               options.update)
  CheckRun('start')
  sysmon = Monitor()
  sysmon.UpdateStatus()
  sysmon.BuildLandingPage()
  runtime = time() - TB.time
  endtime = strftime('%H:%M:%S', localtime())
  TB.logger.info('End Time: %s', endtime)
  TB.logger.info('Time of run: %s seconds', runtime)
  TB.logger.info('Ran with %d threads', sysmon.hostqty)
  CheckRun('stop')

if __name__ == '__main__':
  main(sys.argv)
