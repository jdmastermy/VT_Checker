import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from vt_utils import check_ip_reputation, check_url_reputation, check_hash_reputation
from app_utils import choose_file, save_as_csv, save_as_json, save_as_txt, log_event, headers_map

root = tk.Tk()
root.title("VTChecker by JediMaster")
root.geometry("700x850")

# Variables
direct_input_var = tk.StringVar()
output_filename_var = tk.StringVar()
check_type_var = tk.StringVar(value="IP")
input_selection_var = tk.StringVar(value="Direct Input")
output_format_var = tk.StringVar(value="CSV")

# Function to handle the "Check" button
def check():
    data_type = check_type_var.get()
    if input_selection_var.get() == "Direct Input":
        input_data = direct_input_scrolled_text.get("1.0", "end-1c").splitlines()
    else:
        with open(file_input_entry.get(), 'r') as file:
            input_data = file.readlines()

    if not input_data:
        messagebox.showerror("Error", "No data to process.")
        return

    results = []

    for data in input_data:
        data = data.strip()
        if data:
            if data_type == "IP":
                result = check_ip_reputation(data)
            elif data_type == "URL":
                result = check_url_reputation(data)
            elif data_type in ["MD5 Hash", "SHA1 Hash", "SHA256 Hash"]:
                result = check_hash_reputation(data, data_type)
            results.append(result)
            log_event(f"Processed {data_type} - {data}", logs_scrolled_text)

    if not results:
        messagebox.showerror("Error", "No valid data processed.")
        return

    headers = headers_map[data_type]
    output_format = output_format_var.get()
    output_filename = file_output_entry.get()

    if output_format == "CSV":
        save_as_csv(output_filename, results, headers)
    elif output_format == "JSON":
        save_as_json(output_filename, results)
    else:
        save_as_txt(output_filename, results)

    messagebox.showinfo("Information", "Data saved successfully!")

frame = ttk.Frame(root, padding="20")
frame.pack(padx=10, pady=10, expand=True, fill="both")

# Logo
logo = tk.PhotoImage(file='logo.png')
logo_label = ttk.Label(frame, image=logo)
logo_label.grid(row=0, column=0, columnspan=2, pady=10)

# Choose Type dropdown
ttk.Label(frame, text="Choose Type:").grid(row=1, column=0, sticky="w", pady=5)
ttk.Combobox(frame, textvariable=check_type_var, values=["IP", "URL", "MD5 Hash", "SHA1 Hash", "SHA256 Hash"], state="readonly").grid(row=1, column=0, pady=5, padx=90, sticky="ew")

# Direct input or file input selection
ttk.Radiobutton(frame, text="Direct Input", variable=input_selection_var, value="Direct Input").grid(row=2, column=0, sticky="w", pady=5)
ttk.Radiobutton(frame, text="From File", variable=input_selection_var, value="From File").grid(row=2, column=1, pady=5, sticky="w")

# File input area
file_input_entry = ttk.Entry(frame, textvariable=direct_input_var, width=50)
file_input_entry.grid(row=3, column=0, pady=5, sticky="ew")
file_input_button = ttk.Button(frame, text="Choose File", command=lambda: choose_file(file_input_entry))
file_input_button.grid(row=3, column=1, pady=5, sticky="w")

# Direct input area
ttk.Label(frame, text="Type or Paste your input:").grid(row=4, column=0, sticky="w", pady=5)
direct_input_scrolled_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=70, height=8)
direct_input_scrolled_text.grid(row=5, column=0, columnspan=2, pady=5, padx=10, sticky="ew")


# Output file selection
ttk.Label(frame, text="Output File:").grid(row=6, column=0, sticky="w", pady=5)
file_output_entry = ttk.Entry(frame, textvariable=output_filename_var, width=50)
file_output_entry.grid(row=7, column=0, pady=5, sticky="ew")
file_output_button = ttk.Button(frame, text="Choose File", command=lambda: choose_file(file_output_entry))
file_output_button.grid(row=7, column=1, pady=5, sticky="w")

# Choose Output Format
ttk.Label(frame, text="Output Format:").grid(row=8, column=0, sticky="w", pady=5)
ttk.Combobox(frame, textvariable=output_format_var, values=["CSV", "JSON", "TXT"], state="readonly").grid(row=8, column=0, pady=2, padx=90, sticky="ew")

# Action buttons
check_button = ttk.Button(frame, text="Check", command=check)
check_button.grid(row=9, column=0, pady=10)
reset_button = ttk.Button(frame, text="Reset", command=lambda: [direct_input_scrolled_text.delete(1.0, tk.END), logs_scrolled_text.delete(1.0, tk.END)])
reset_button.grid(row=9, column=0, pady=60, sticky="e")

# Log area
ttk.Label(frame, text="Logs:").grid(row=10, column=0, sticky="w", pady=5)
logs_scrolled_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=70, height=8)
logs_scrolled_text.grid(row=11, column=0, columnspan=2, pady=5, padx=10, sticky="ew")

root.mainloop()
