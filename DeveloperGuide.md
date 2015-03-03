
# Introduction #

This document explains the internal structure of Watchdog, and will assist when adding new features, fixing bugs, or changing the architecture.

# Overview #

Watchdog is written in Python. It was tested on Python 2.6, but anything as new as Python 2.4 will probably work. Watchdog depends on the following modules:
  * logging, logging-handlers - to log messages to files, and also to turn over log files after they reach a certain size.
  * optparse - to handle command line arguments.
  * os, sys - to handle os and system level methods.
  * threading, Queue - watchdog uses threads to connect to remote machines, and a Queue to populate a list of hosts into the threaded class.
  * IPy - used to determine if a host is actually a valid IP address.
  * time - for time keeping operations.
  * shutil -high level file operations.
  * yaml - to parse the configuration file, which is in yaml format.

Watchdog will first determine how many clients need to be monitored, and based on that it will create one thread for each client. This has been tested with over 100 machines; however, if the number of clients grows to the thousands then a different approach might be needed. A Queue is used to populate the thread class, MonitorThread, with hosts to monitor. The Queue class has been subclassed to provide a timeout value, in case any of the threads get wedged and don't return.

## Watchdog Classes ##

  * Monitor - provides the overall controlling logic for watchdog, and is responsible for initializing all of the other classes that are used to fetch and update data, and create HTML files and graphs.
  * TestBed - a global class used to hold global variables and client data from each machine being monitored.
  * Resource - contains structures and methods required to collect resource information on each monitored system.
  * RRD - provides all interfaces into RRDTool to create, update and graph resources.
  * TBQueue - a subclass of Queue, which provides a queue with a timeout.
  * Host - provides a small structure for each monitored system. This could be expanded to provide additional data.
  * MonitorThread - a small threaded class that gets hosts from a queue and creates a RemoteWorker object for each monitored host.
  * RemoteWorker - provides all of the methods for accessing remote hosts and getting data from them.

## Watchdog Global Functions ##
The following functions are available for all classes to use:
  * SetLogger - creates a logger object for logging all messages. Messages can also be streamed to stdout.
  * CheckRun - checks if watchdog is currently running.
  * ParseArgs - parses all command line arguments.

# Flow Control #
Watchdog utilizes multiple classes to provide it's feature set. It initially parses the command line options and then initializes a global TestBed object. This object will hold various global configuration variables, as well as data from all of the monitored hosts. To get a list of the monitored hosts and some of the global options, it reads it's configuration file (YAML format) and stores these values in some of the TestBed attributes. Watchdog then initializes a Monitor object which in turn will create classes as needed to get resource data from all monitored hosts, and then build a new landing page which summarizes each host's status and provides links to a hardware inventory and graphs for each host. See the flow control diagram for a high level illustration.

![http://system-watchdog.googlecode.com/svn/wiki/watchdog-flow.png](http://system-watchdog.googlecode.com/svn/wiki/watchdog-flow.png)

The MonitorThread object will create one RemoteWorker for each host that is monitored.  RemoteWorker's depend on paramiko's ssh functionality. Additionally, the hosts must have previously been set up to allow the root account key based ssh access without a password.

The RRD class is preconfigured to expect data updates within 5 minute intervals; consequently ensure that updates are being run at this frequency.

# Detailed Design #

See the class diagram below for details on class attributes and methods.

![http://system-watchdog.googlecode.com/svn/wiki/watchdog-class.png](http://system-watchdog.googlecode.com/svn/wiki/watchdog-class.png)

The TestBed class is global in scope, in order to provide a structure to hold global attributes, lists, and dictionaries. It is also the structure that will keep all gathered data and formatted data for the RRDTool.

# Coding Style #
In general, we will follow the style guide published by Guido van Rossum on
python.org:
  * http://www.python.org/doc/essays/styleguide.html
  * Deviations:
    * No tabs: 2 spaces for indentation
  * Useful things to know:
    * Naming Conventions
```
       ClassesLikeThis
       _PrivateClass
       MethodNames
       _PrivateMethods
       variable_name
       CONSTANTS
```
    * Err on the side of having longer, meaningful names.
    * Comments
      * """Use doc strings, as this can be helpful for producing documents."""
        * Doc Strings should be very concise and descriptive about what something does, not how it does it.
      * # Use this style when you need a note of explanantion.
        * Either above or to the right of code.
    * 80 characters per line (line wraps get ugly)
    * Try to adhere to the style you see in the code. _Consistency is key_.