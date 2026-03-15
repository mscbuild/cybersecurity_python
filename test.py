import customtkinter as ctk
import speedtest
import threading

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.geometry("420x420")
app.title("Internet Speed Test")


title = ctk.CTkLabel(app, text="Internet Speed Test", font=("Arial", 26, "bold"))
title.pack(pady=20)

download_label = ctk.CTkLabel(app, text="Download: -- Mbps", font=("Arial", 18))
download_label.pack(pady=10)

upload_label = ctk.CTkLabel(app, text="Upload: -- Mbps", font=("Arial", 18))
upload_label.pack(pady=10)

ping_label = ctk.CTkLabel(app, text="Ping: -- ms", font=("Arial", 18))
ping_label.pack(pady=10)

status_label = ctk.CTkLabel(app, text="Press Start", font=("Arial", 14))
status_label.pack(pady=10)

progress = ctk.CTkProgressBar(app, width=250)
progress.set(0)
progress.pack(pady=15)


def run_test():
    try:
        progress.set(0.2)
        status_label.configure(text="Finding server...")

        st = speedtest.Speedtest()
        st.get_best_server()

        progress.set(0.4)
        status_label.configure(text="Testing download...")

        download = st.download() / 1_000_000
        download_label.configure(text=f"Download: {download:.2f} Mbps")

        progress.set(0.7)
        status_label.configure(text="Testing upload...")

        upload = st.upload() / 1_000_000
        upload_label.configure(text=f"Upload: {upload:.2f} Mbps")

        ping = st.results.ping
        ping_label.configure(text=f"Ping: {ping:.2f} ms")

        progress.set(1)
        status_label.configure(text="Test Completed")

    except Exception as e:
        status_label.configure(text=f"Error: {e}")


def start_test():
    progress.set(0)
    thread = threading.Thread(target=run_test)
    thread.start()


start_button = ctk.CTkButton(app, text="Start Speed Test", command=start_test)
start_button.pack(pady=20)


app.mainloop()
