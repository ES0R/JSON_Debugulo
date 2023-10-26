import cv2
import os

# Load the video
video = cv2.VideoCapture('test.mp4')

# Check if video opened successfully
if not video.isOpened():
    print("Error: Could not open video.")
    exit()

# Create subfolder to store frames
subfolder = 'frames'
os.makedirs(subfolder, exist_ok=True)  # The exist_ok parameter allows the command to succeed if the folder already exists

frame_number = 0
while True:
    ret, frame = video.read()
    if not ret:
        break  # Break the loop if we reach the end of the video

    filename = os.path.join(subfolder, f'frame{frame_number:04d}.jpg')  # Specify path to save frames in the subfolder
    cv2.imwrite(filename, frame)
    frame_number += 1

video.release()
cv2.destroyAllWindows()
