

# Prerequisites #

In order to use WatchDog you'll need the following programs installed:
  * Server _system running watchdog_
    * Python
    * RRDTool
  * Client _systems being monitored_
    * lshw
    * dmidecode

Chances are if your clients are modern linux distributions, they will have all of the required programs already installed. For the server, you may need to install RRDTool. RRDTool is used to produce graphs and charts.

The RRD databases are setup to expect input at least once every 5 minutes. Therefore, the machine where you plan on running watchdog.py needs to be powerful enough to complete one run against all of your client machines in less than 5 minutes. It's recommended that you set up a cron job to execute WatchDog every 5 minues, and then run it once an hour to generate new graphs.


# Setup #

In order to collect details on each of your client systems, you need to configure it to enable ssh as root without a password. The root account is used because it executes lshw and dmidecode, both of which require root access.

---

## Configuring SSH ##
Perform the following actions on the machine where you plan to run watchdog, running as the user that will be running watchdog:
  * Generate a rsa key pair:
    * `  ssh-keygen -t rsa  `
    * accept the defaults, and do not enter a passphrase
  * you should now have id\_rsa and id\_rsa.pub in your ~/.ssh/
On each client machine:
  * Copy the id\_rsa.pub file to /root/.ssh/authorized\_keys
  * If this file already exists, append id\_rsa.pub to the end of the file.
  * Ensure the permissions are 700:
    * `  sudo chmod 700 /root/.ssh/authorized_keys  `
  * For more information, see:
    * http://www.go2linux.org/ssh-login-using-no-password

---

## Configuration File ##
WatchDog will use information in the configuration file ( **watchdog.yaml** ) to know what hosts are included in your test bed and also some general configuration variables. Before running watchdog, set up the following:
  * testbeds: list any systems that you plan to monitor in the testbeds section.
    * By default, watchdog will look for a default testbed.
    * Each system should contain the following
      * hostname or IP address
      * a descriptive label
    * The hostname should be separated from the label with a ':', and end with a comma.
    * Sample listings:
```
      testbeds:
        default:
          [
           superman: IBM_NetVista,
           batman: Dell_T3500,
           spiderman: HP_Z600,
           172.16.1.4: Lenovo_S20,
           ]
         test_lab:
           [
            pkilab1: Dell_P390,
            pkilab2: HP_XW4300,
            pkilab3: Lenovo_S10,
           ]
```
    * The sample above has two testbeds. The default test bed has 4 machines, and the test\_lab testbed has 3 machines. !Watchdog will use the first field of each host line to access the machine, so ensure they are accessible with a short hostname. If not, add a fully qualified domain name or add a subdomain.
  * site
    * The site section has configuration options that are specific to your site. You need to add the following paths for:
    * **caption** - A string that will be displayed above the table of monitored systems.
    * **homedir** - this will be the top level directory where watchdog stores all of it's files.
    * **privkey** - this is the pathname to your rsa private key. In most cases this will probably be ~/.ssh/id\_rsa
    * **rundir** - this is a directory where watchdog will store some temporary files. It needs to be writable by the user running watchdog. In most cases it is fine to use the same directory as **homedir**.
    * **urlhome** - The url of the systemhealth home directory. If your homedir is being served by a web server, than you'll want a real url address. On the other hand, if you are simply using a browser to open an html file, then it might be in the form of file:///.
      * url: http://mywebserver/systemheatlh/
      * file: [file:///var/tmp/systemhealth/](file:///var/tmp/systemhealth/)
    * Here is a sample site section of the configuration file:
```
       site:
         [
          caption: Graph updated every hour,
          homedir:/var/tmp/systemhealth,
          privkey: /home/kdlucas/.ssh/id_rsa,
          rundir: /var/tmp/systemhealth,
          urlhome: 'file:///var/tmp/systemhealth/',
         ]
```
    * _Notice the quotes around the urlhome value, as they are needed when a value contains the ':' character._
  * Download the watchdog.tgz file, and copy the **.png files and the table.css file to your homedir, which you configured above.**

# Running Watch Dog #
For long term use, you'll want to automate the execution of watchdog, most likely putting it in a crontab. Initially you'll want to execute it manually to ensure it is running properly. Watchdog support the following options:
  * --conffile - if you are using multiple configuration files, you can tell it which one to use.
    * default: watchdog.yaml
  * --debug - Sets the debug level. If you are trying to troubleshoot, you'll want to set this to the debug level. It supports debug, info, warning, error, and critical.
> > default: info
  * --graph - If set to True, it will create new graphs based on the latest data.
    * default: False.
  * --help - Display available options.
  * --html - If set to True, it will generate new html pages for each monitored host.
    * default: False.
  * --logfile - In case you need to specify a different logfile name.
    * default: update.log
  * --log\_to\_stdout - If set to True, all messages will be sent to stdout, in addition to the log file.
    * default: False
  * --testbed - The name of the testbed to use. This must match one of the strings in the testbed section of your configuration file.
    * default: default
  * --update - If set to True, it will collect new resource data from all hosts in the test bed.
    * default: True.
  * --version - display the version number and exit.
## Sample Execution ##
  * To only gather updates from the default testbed:
    * `  ./watchdog.py  `
  * To gather updates, and build new html files and graphs:
    * `  ./watchdog.py --html True --graph True  `
  * To run in debug mode and send all output to std out:
    * `  ./watchdog.py --debug debug --log_to_stdout True --html True --graph True  `

# Crontab Setup #
Since watchdog is preconfigured to expect input at least every 5 minutes, it's recommended that you set it up so that data updates are obtained at least every 5 minutes. Unless you have a pressing need to view updated graphs often, it is better to build the graphs less often as they will use up a good deal more of processing power. In fact, the html landing page assumes the graphs are updated once per hour. If you need to change this frequency, you should change the caption variable in the site section of the configuration file.

Let's say you have a copy of watchdog.py and watchdog.yaml in /var/tmp/systemhealth/ .
To set up watchdog to update every 5 minutes, and to build new graphs and html files every hour, do the following:
  * Save the following to /tmp/watchdog.crontab:
```
       */5 * * * * /var/tmp/systemhealth/watchdog.py
       0 * * * * /var/tmp/systemhealth/watchdog.py --html True --graph True --update False
```
  * Load the file into crontab: `  crontab /tmp/watchdog.crontab  `

# Exploring Watchdog #
![http://system-watchdog.googlecode.com/svn/wiki/watchdog-ov.png](http://system-watchdog.googlecode.com/svn/wiki/watchdog-ov.png)

Once watchdog begins to run, it will start to build historical data from all of the systems it is monitoring. After it has build up some data (generally it takes about 3 or 4 updates) you will start to see graphs displaying usage data in the various categories of resources you are monitoring.

  * Landing Page  - index.html
    * Will list a table of all monitored systems.
    * Will have links to watchdog logs.
    * Will display a red background if it cannot access a client.
    * Will provide a link to hardware inventory of the system, by clicking on the host name.
    * Will provide a link to resource graphs, by clicking on the graph icon.
    * Each host graph will contain:
      * links to specific time periods
      * links to specific resources for all time periods
      * vertical bars to display changes in bios, release, or system model.

