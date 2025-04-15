import os
import base64

"""
This file is used when filling the database with dummy data.
Check fill_db.starting_stories

If you want to change the images, simply change img_name below or replace the image in the images folder.
"""


def convert_img(img_name: str) -> str:
    file_path = os.path.dirname(__file__)
    img_path = os.path.join(file_path, img_name)
    with open(img_path, "rb") as i:
        b64img = base64.b64encode(i.read()).decode("utf-8")
    return b64img


img1 = convert_img("images/fantasy.png")
img2 = convert_img("images/horror.png")
img3 = convert_img("images/scifi.png")


if __name__ == "__main__":
    if img1:
        print(img1[:100])
        print(img2[:100])
        print(img3[:100])
    else:
        print("img1 is None")
