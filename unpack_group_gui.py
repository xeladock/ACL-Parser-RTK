import ipaddress
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext

from unpack_group_core import get_object_group
from unpack_group_parser import CiscoASAParser
# def check_ip(objects, ranges, ip):
#     if not ip:
#         return [(obj["text"], False) for obj in objects]
#
#     target = ipaddress.ip_address(ip)
#
#     result = []
#
#     for obj in objects:
#
#         if target in obj["network"]:
#             result.append((obj["text"], True))
#         else:
#             result.append((obj["text"], False))
#
#     for r in ranges:
#
#         if r["start"] <= target <= r["end"]:
#             result.append((r["text"], True))
#         else:
#             result.append((r["text"], False))
#
#     return result


# def search():
#
#     device = device_entry.get()
#     group = group_entry.get()
#     ip = ip_entry.get()
#
#     output.delete("1.0", tk.END)
#
#     objects, err = get_object_group(device, group)
#
#     if err:
#         output.insert(tk.END, err)
#         return
#
#     target = ipaddress.ip_network(ip, strict=False)
#
#     for obj in objects:
#
#         net = ipaddress.ip_network(obj, strict=False)
#
#         if net.overlaps(target):
#             output.insert(tk.END, obj + "  <-- Объект найден!\n", "bold")
#         else:
#             output.insert(tk.END, obj + "\n")


# root = tk.Toplevel()
# root.title("Object Group Viewer")
#
# frame = ttk.Frame(root, padding=10)
# frame.grid()



# root.mainloop()
def run_og_viewer(parent=None):
    def search():

        device = device_entry.get()
        group = group_entry.get()
        ip = ip_entry.get()

        output.delete("1.0", tk.END)

        parser, objects, err = get_object_group(device, group)

        if err:
            output.insert(tk.END, err)
            return

        if not ip:
            for obj in objects:
                output.insert(tk.END, obj["text"] + "\n")
            return
        # ranges = parser.parse_object_ranges()

        result = parser.check_ip(objects, ip)

        for text, match in result:

            if match:
                output.insert(tk.END, text + "\n", "bold")
            else:
                output.insert(tk.END, text + "\n")

    window = tk.Toplevel(parent)  # вместо Tk()
    window.title("Object Group Viewer")

    frame = ttk.Frame(window, padding=10)
    frame.grid()
    ttk.Label(frame, text="Устройство").grid(row=0, column=0)
    device_entry = ttk.Entry(frame, width=40)
    device_entry.grid(row=0, column=1)

    ttk.Label(frame, text="Object-group").grid(row=1, column=0)
    group_entry = ttk.Entry(frame, width=40)
    group_entry.grid(row=1, column=1)

    ttk.Label(frame, text="IP / Network").grid(row=2, column=0)
    ip_entry = ttk.Entry(frame, width=40)
    ip_entry.grid(row=2, column=1)

    search_btn = ttk.Button(frame, text="Поиск", command=search)
    search_btn.grid(row=3, column=1)

    output = scrolledtext.ScrolledText(frame, width=60, height=20)
    output.grid(row=4, column=0, columnspan=2)

    output.tag_config("bold", font=("TkDefaultFont", 10, "bold"))

# def run_gui():
#     """Создаёт окно Object-Group Viewer"""
#     window = tk.Toplevel()  # Важно: Toplevel, а не Tk
#     window.title("Object-Group Viewer")
#     # window.geometry("600x400")
#
#     # Здесь ваш GUI: entry, кнопки, вывод и т.д.
#     tk.Label(window, text="Пример OG Viewer").pack()