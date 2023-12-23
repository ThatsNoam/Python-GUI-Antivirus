# imports
from tkinter import *
from tkinter import filedialog
import threading
import requests
import time
import os
# global variable for background animation
background_animation_id = None

# function that creates a window (mainloop)
def create_window():
    window = Tk() # instance of a window
    window.geometry("900x650") # window size
    window.minsize("900","650") # window minimum size
    window.maxsize("900","650") # window maximum size

    window.title("AntiVirus") # window title

    # function that creates a new background when Help button is clicked.
    def show_help():
        global background_animation_id
        if background_animation_id is not None:
            window.after_cancel(background_animation_id)
            background_animation_id = None
        # hide elements
        scan_button.place_forget()
        scan_path_button.place_forget()
        result_label.place_forget()
        path_status_label.place_forget()
        help_button.place_forget()  # also hide the help button

        # change the background to 'help.png'
        help_photo = PhotoImage(file="help.png")
        background_label.config(image=help_photo)
        background_label.image = help_photo  # keep a reference (important in tkinter)

        # show the back button
        back_button.place(x=811, y=594)  # position of the back button

    # function that returns to the main window
    def back_to_main():
        global background_animation_id
        # restore hidden elements
        scan_button.place(x=550, y=410)
        scan_path_button.place(x=100, y=410)
        result_label.place(x=70, y=520)
        path_status_label.place(x=520, y=520)
        help_button.place(x=811, y=594)  # restore the help button

        # reset the background image
        background_label.config(image=background_photo)
        background_label.image = background_photo  # reset reference (important in tkinter)

        back_button.place_forget() # hide the back button
        animate_background() # return the animation to the window


    # make 2 global photos.
    global background_photo, background_photo_2
    background_photo = PhotoImage(file="AntiVirus_Image.png")
    background_photo_2 = PhotoImage(file="AntiVirus_Image_2.png")


    # function to animate the background
    def animate_background():
        global background_animation_id
        current_image = background_label.cget("image")
        # choose which image to use next
        if current_image == str(background_photo_2):
            next_image = background_photo
        else:
            next_image = background_photo_2
        # apply the next image
        background_label.config(image=next_image)
        background_label.image = next_image

        # schedule the next change
        background_animation_id = window.after(1000, animate_background) # 1 second delay


    # make background label.
    background_label = Label(window, image=background_photo)
    background_label.place(x=0, y=0)

    # start the animation
    animate_background()

    # make the scan_button.
    scan_button = Button(window, text="Scan Path", font=("System", 35, "bold"),
                         command=lambda: start_scan_thread(window, path_status_label, scan_type='path'),
                         relief=FLAT, bg="green", fg="white", activebackground="#45a049")
    scan_button.place(x=550, y=415) # place the button.

    # make the scan_path_button.
    scan_path_button = Button(window, text="Scan File", font=("System",35, "bold"),
                              command=lambda: start_scan_thread(window, result_label, scan_type='file'),
                              relief=FLAT, bg="green", fg="white", activebackground="#45a049")
    scan_path_button.place(x=100, y=415) # place the button.

    # functions to change button color on hover
    def on_enter(e, button):
        button.config(background="#45a049")

    def on_leave(e, button):
        button.config(background="green")

    # bind the hover effect for the scan_button
    scan_button.bind("<Enter>", lambda e: on_enter(e, scan_button))
    scan_button.bind("<Leave>", lambda e: on_leave(e, scan_button))

    # bind the hover effect for the scan_path_button
    scan_path_button.bind("<Enter>", lambda e: on_enter(e, scan_path_button))
    scan_path_button.bind("<Leave>", lambda e: on_leave(e, scan_path_button))

    # make result label
    result_label = Label(window, text="No File Selected",fg="orange", font=("System", 30),bg="black")
    result_label.place(x=70, y=520)  # place the result label.

    path_status_label = Label(window, text="No Path Selected", fg="orange", font=("System", 30), bg="black")
    path_status_label.place(x=520, y=520)

    exit_button = Button(window, text="EXIT", font=("System", 20, "bold"),
                         command=window.destroy,  # command to close the window
                         relief=FLAT, bg="purple", fg="white", activebackground="purple")
    exit_button.place(x=0, y=594)  # place the exit_button.
    help_button = Button(window, text="HELP", font=("System", 20, "bold"),
                         command=show_help, relief=FLAT, bg="purple", fg="white", activebackground="purple")
    help_button.place(x=811, y=594)

    # back button - initially hidden
    back_button = Button(window, text="BACK", font=("System", 20, "bold"),
                         command=back_to_main, relief=FLAT, bg="purple", fg="white", activebackground="purple")

    window.mainloop() # make this window the mainloop.


#-------------------------------------------------------------------------------------------------------------------

# function that checks if a file is clean or infected.
def has_virus(file_name, result_label):
    result_label.config(text="Scanning...", fg="blue",bg="black")
    url = "https://www.virustotal.com/api/v3/files"
    api_key = "<Your API KEY>"
    with open(file_name, "rb") as file:
        files = {"file": (file_name, file)}
        headers = {"accept": "application/json", "x-apikey": api_key}
        response = requests.post(url, files=files, headers=headers)

    if response.ok:
        data = response.json()
        file_id = data['data']['id']
        url2 = f"https://www.virustotal.com/api/v3/analyses/{file_id}"
        time.sleep(15)
        response = requests.get(url2, headers=headers)
        if response.ok:
            analysis_results = response.json()
            stats = analysis_results.get('data', {}).get('attributes', {}).get('stats', {})
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)

            if malicious_count == 0 and suspicious_count == 0:
                result_label.after(0, lambda: result_label.config(text="File is clean.", fg="green", bg="black"))
                return False  # file is clean
            else:
                result_label.after(0, lambda: result_label.config(text="File is infected.", fg="red", bg="black"))
                return True  # file is infected
        else:
            print(f"Error retrieving analysis: {response.status_code}")
    else:
        print(f"Error submitting file: {response.status_code}")

# function that allows the GUI to remain responsive in the scanning process.
def start_scan_thread(master, label, scan_type='file'):
    if scan_type == 'file':
        path = filedialog.askopenfilename(master=master)
        if path:
            threading.Thread(target=has_virus, args=(path, label), daemon=True).start()
    elif scan_type == 'path':
        path = filedialog.askdirectory(master=master)
        if path:
            threading.Thread(target=scan_path, args=(path, label), daemon=True).start()

# function that uses the has_virus function to check if a file is clean or infected.
def scan_file(master, result_label):
    file_path = filedialog.askopenfilename(master=master)
    if file_path:
        infected = has_virus(file_path)
        if infected:
            result_label.config(text="File is infected.", fg="red",bg="black")
        else:
            result_label.config(text="File is clean.", fg="green",bg="black")

# function that checks if all the files under a path are infected or clean.
def scan_path(path, path_status_label):
    path_status_label.config(text="Scanning...", fg="blue", bg="black")
    path_infected = False  # flag to keep track of infection status

    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            # check each file for a virus
            infected = has_virus(file_path, path_status_label)
            if infected:
                path_infected = True

    # update the path_status_label based on whether any file was infected
    if path_infected:
        path_status_label.config(text="Path is Infected.", fg="red", bg="black")
    else:
        path_status_label.config(text="Path is Clean.", fg="green", bg="black")




# main function.
def main():
    create_window() # create the window.

main()