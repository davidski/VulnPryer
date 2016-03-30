from yapsy.IPlugin import IPlugin


class IVulnPryer:
    """Base class for all VP plugins"""
    def set_config(self, option, value):
        """Safely set a config option."""
        self.setConfigOption(option, value)

    def get_config(self, option, default=None):
        """Safely get a config option."""
        try:
            result = self.getConfigOption(option)
        except:
            result = default
        return result


class IStorePlugin(IPlugin, IVulnPryer):
    """Base class for store plugins"""
    CATEGORY = "Store"

    def __init__(self):
        IPlugin.__init__(self)


class IFeedPlugin(IPlugin, IVulnPryer):
    """Base class for feed plugins"""
    CATEGORY = "Feed"
    pass


class IScorePlugin(IPlugin, IVulnPryer):
    """Base class for score plugins"""
    CATEGORY = "Score"
    pass


class IApplyPlugin(IPlugin, IVulnPryer):
    """Base class for apply plugins"""
    CATEGORY = "Apply"
    pass
