import os
from PIL import Image
from PIL import ExifTags

folder = "thanks"

for ii, img_path in enumerate(os.listdir(folder)):
    img_path = os.path.join(folder, img_path)
    os.rename(img_path, os.path.join(folder, f"{ii}_.jpg"))

for ii, img_path in enumerate(os.listdir(folder)):
    img_path = os.path.join(folder, img_path)
    os.rename(img_path, os.path.join(folder, f"{ii}.jpg"))

try:
    os.makedirs(os.path.join("compressed", folder))
except FileExistsError:
    pass

for ii, img_path in enumerate(os.listdir(folder)):
    img_path = os.path.join(folder, img_path)

    img = Image.open(img_path)

    try:
        exif = dict((ExifTags.TAGS[k], v) for k, v in img._getexif().items() if
                    k in ExifTags.TAGS)

        if exif["Orientation"] == 3:
            img = img.rotate(180, expand=True)
        elif exif["Orientation"] == 6:
            img = img.rotate(270, expand=True)
        elif exif["Orientation"] == 8:
            img = img.rotate(90, expand=True)
    except:
        ...

    img.save(os.path.join("compressed", img_path), optimize=True, quality=15)