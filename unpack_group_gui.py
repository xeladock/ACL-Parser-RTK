
import tkinter as tk
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

def fix_entry_shortcuts(entry_widget):
    # Ctrl+A — выделить всё
    def select_all(event=None):
        entry_widget.focus_set()
        entry_widget.selection_range(0, tk.END)
        return "break"

    # Ctrl+C
    def copy(event=None):
        entry_widget.event_generate("<<Copy>>")
        return "break"

    # Ctrl+X
    def cut(event=None):
        entry_widget.event_generate("<<Cut>>")
        return "break"

    # Ctrl+V — вставка с заменой выделенного
    def paste(event=None):
        try:
            selection = entry_widget.selection_get()
            # если выделен текст — удалить его
            entry_widget.delete("sel.first", "sel.last")
        except tk.TclError:
            # ничего не выделено — просто вставляем в позицию курсора
            pass
        entry_widget.event_generate("<<Paste>>")
        return "break"

    # биндим все варианты (нижний и верхний регистр)
    entry_widget.bind("<Control-a>", select_all)
    entry_widget.bind("<Control-A>", select_all)
    entry_widget.bind("<Control-c>", copy)
    entry_widget.bind("<Control-C>", copy)
    entry_widget.bind("<Control-v>", paste)
    entry_widget.bind("<Control-V>", paste)
    entry_widget.bind("<Control-x>", cut)
    entry_widget.bind("<Control-X>", cut)


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
                # print("3")
            return
        # ranges = parser.parse_object_ranges()

        result = parser.check_ip(objects, ip)
        print(result)
        for text, match in result:
            # print(text)
            if match:
                output.insert(tk.END, text + "\n", "bold" )
                # output.insert(tk.END, "Found"+"\n")
                # print("1")
                print(text)
            else:
                output.insert(tk.END, text + "\n")
                # print("2")
                # print(text)
    window = tk.Toplevel(parent)  # вместо Tk()
    window.title("Object Group Viewer")
    window.configure(bg="#f0f0f0")
    window.resizable(False, False)
    frame = tk.Frame(window)
    frame.grid()
    # frame.grid(sticky="nw", padx=12, pady=12) //отступы
    frame.configure(bg="#f0f0f0")
    frame.grid_columnconfigure(0, weight=0)
    frame.grid_columnconfigure(1, weight=1)
    frame.grid_anchor("w")
    tk.Label(frame, text="Устройство:",bg="#f0f0f0").grid(row=0, column=0, sticky="e",padx=(30, 2))

    device_entry = tk.Entry(frame, width=40)
    device_entry.grid(row=0, column=1, sticky = "w", padx = (2,0))
    fix_entry_shortcuts(device_entry)

    tk.Label(frame, text="Object-group:",bg="#f0f0f0").grid(row=1, column=0, sticky="e", padx=(10, 2))
    group_entry = tk.Entry(frame, width=40)
    group_entry.grid(row=1, column=1,  sticky="w", padx=(2, 0))
    fix_entry_shortcuts(group_entry)

    tk.Label(frame, text="IP / Network:",bg="#f0f0f0").grid(row=2, column=0,sticky="e", padx=(10, 2))
    ip_entry = tk.Entry(frame, width=40)
    ip_entry.grid(row=2, column=1, sticky="w", padx=(2, 0))
    fix_entry_shortcuts(ip_entry)

    search_btn = tk.Button(frame, text="Поиск", command=search)
    search_btn.grid(row=3, column=1,sticky="w",padx=120,pady=(4, 4))

    output = scrolledtext.ScrolledText(frame, width=63, height=25)
    output.grid(row=4, column=0, columnspan=2)

    output.tag_config("bold", font=("TkDefaultFont", 10, "bold"))
