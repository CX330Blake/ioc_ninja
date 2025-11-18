import os
from binaryninja import PluginCommand
from binaryninjaui import UIContext

from .ui import IoCNinjaWidget


def show_ioc_ninja_dialog(bv):
    if bv is None:
        return

    # Create a new tab with our widget instead of a popup dialog
    ctx = UIContext.activeContext()
    if ctx is None:
        return
    widget = IoCNinjaWidget(None, "IoC Ninja", bv)
    # Create tab and give it focus
    ctx.createTabForWidget("IoC Ninja", widget)


PluginCommand.register(
    "IoC Ninja", "Open IoC Ninja as a pop-up window", show_ioc_ninja_dialog
)
