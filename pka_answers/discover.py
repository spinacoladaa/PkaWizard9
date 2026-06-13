"""discover - vind .pka-bestanden in een map."""
import os
import glob


def find_pka(folder=None):
    """Geef gesorteerde lijst .pka-paden in folder (default = huidige werkmap)."""
    folder = folder or os.getcwd()
    return sorted(glob.glob(os.path.join(folder, "*.pka")))
