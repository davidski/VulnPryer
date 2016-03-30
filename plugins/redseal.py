#!/usr/bin/env python

import VulnPryerPluginClass as plugintypes

import logging
logger = logging.getLogger('vulnpryer.apply')


class IRedSeal(plugintypes.IApplyPlugin):
    """Apply to RedSeal TRL plugin."""

    def load_source(self):
        """Load the source."""
        pass

    def prioritize(self):
        """Loop over the data and apply the new scores."""
        pass

    def write_output(self):
        """Send modified data stream to output."""
        pass

    def send_notification(self):
        """
        When a vuln is modified, send a notification to channel of choice.
        """
        pass

if __name__ == "__main__":
    modify_trl('/tmp/trl.gz')
