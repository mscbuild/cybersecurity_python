import pyautogui
import time

# Set the position of the username and password fields
username_field = (600, 400)
password_field = (600, 450)

# Set the position of the login button
login_button = (600, 500)

# Enter the username and password
pyautogui.click(username_field)
pyautogui.typewrite('admin')
pyautogui.click(password_field)
pyautogui.typewrite('password')

# Click the login button
pyautogui.click(login_button)

# Wait for the login to complete
time.sleep(5)
