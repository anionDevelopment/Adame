# Configuration

## Adame.configuration

This file is the main configuration-file for an application-environment managed by Adame.

The following configuration-items are available:

TODO

### Hook-scripts

The following configuration-items in the section `general` allow to run a custom shell-script (executed with `sh`) at certain points in time when the container gets started or stopped (for example by the commands `start`, `stop`, `startadvanced` and `stopadvanced`):

| Configuration-item | Point in time when the script will be executed |
| --- | --- |
| `prestartscript` | Before the container will be started. |
| `poststartscript` | After the container was started. |
| `prestopscript` | Before the container will be stopped. |
| `poststopscript` | After the container was stopped. |

If the value of a configuration-item is empty then no script will be executed.
A relative path will be resolved relative to the folder `Configuration`. The script will also be executed with the folder `Configuration` as working-directory.

The scripts `poststartscript` and `poststopscript` will also be executed if the start respectively the stop of the container failed.

These configuration-items replace the configuration-items `prescript` (now `prestartscript`) and `postscript` (now `poststopscript`) which were used before Adame v2.1.0. Existing repositories will be migrated automatically.

## ApplicationProvidedSecurityInformation.xml

TODO

## Networktraffic.Custom.rules

This is the file where custom application-related rules (typically one rule per line) for the used IDS can be stored in.

`__localipaddress__` can be used in this file as placeholder for the IP-address of the network-interface defined in the file `Adame.configuration`. Adame will automatically replace this placeholder in the file `Networktraffic.Generated.rules` when the configuration will be re-applied.

## LogfilePatterns.txt

TODO

## Security.configuration

TODO

## docker-compose.yml

This file can be edited arbitrarily as long as it satisfies the [specification  for docker-compose-files](https://docs.docker.com/compose/compose-file/) provided by docker.
