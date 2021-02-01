# pi_boincmon
The third best thing after the invention of garlic bread and pi_wrestled. At least for BOINC users which want to leverage their pi_wrestled-powered LEDs array. Witten in python3, it provides a framework for querying BOINC hosts to analyze the number of running BOINC tasks and updating LEDs to reflect their status (expected amount of running tasks, below expected ammount, BOINC not running, etc).

## What do I need to do to get it running on my Raspberry Pi?

Paramiko is used for implementing the ssh client connections to monitored hosts. You can install it manually on Debian/Ubuntu, as follows:
```
sudo apt-get install python3-paramiko
```

## Do I need to run it on a Raspberry Pi?

No, not really. Any OS with a working python3.6+ installation will do.

## Does this only work with pi_wrestled? Can I trigger other sort of REST calls?

There's some degree of flexibility in terms of payload, so yes, in theory you could even do that without any rewrites. A more likely scenario would still involve some code changes.

## How do I configure this thing?

Look under the /conf folder for a sample config file. You can add as many host entries as you like, just number them incrementally, as per the sample.

## What's with the wierd passwords?

I've written a separate module to encrypt the ssh user passwords of the monitored hosts using a master password. To generate the encrypted text that you need to add in the config file just run pi_password.py and follow the on-screen prompts.
