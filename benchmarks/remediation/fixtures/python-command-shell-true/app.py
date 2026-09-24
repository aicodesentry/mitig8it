"""Thumbnail rendering jobs."""
import subprocess


def render_thumbnail(source_name):
    subprocess.run("convert " + source_name + " -resize 200x200 thumb.png", shell=True, check=True)
    return "thumb.png"
