import ipaddress
import tkinter as tk
from tkinter import scrolledtext

from paramiko.common import four_byte

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
# bind("<Shift-F1>", lambda e: run_og_viewer())


def validate_ip_or_network2(value: str) -> bool:
    if not value or value.lower() == "any":
        return True
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

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
    def paste(event):
        widget = event.widget

        try:
            text = widget.selection_get(selection="CLIPBOARD")
        except tk.TclError:
            return "break"

        text = text.strip()

        # если есть выделение — удалить его
        try:
            widget.delete("sel.first", "sel.last")
        except tk.TclError:
            pass

        # вставка в позицию курсора
        widget.insert(tk.INSERT, text)

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

def clean_text(text) -> str:

        if not text:
            return ""

        text = text.split(':', 1)[0].strip()
        text = text.strip()
        return text

def fix_device_entry(entry_widget):
    """Специальная версия для device_entry с очисткой текста"""

    def select_all(event=None):
        entry_widget.selection_range(0, tk.END)
        return "break"

    def copy(event=None):
        entry_widget.event_generate("<<Copy>>")
        return "break"

    def cut(event=None):
        entry_widget.event_generate("<<Cut>>")
        return "break"

    def paste(event=None):
        try:
            clipboard = entry_widget.clipboard_get()
            cleaned = clean_text(clipboard)

            # Удаляем выделенный текст, если есть
            try:
                entry_widget.delete("sel.first", "sel.last")
            except tk.TclError:
                pass

            entry_widget.insert(tk.INSERT, cleaned)

        except tk.TclError:
            pass  # буфер пуст

        return "break"

    # Биндинги
    entry_widget.bind("<Control-a>", select_all)
    entry_widget.bind("<Control-A>", select_all)
    entry_widget.bind("<Control-c>", copy)
    entry_widget.bind("<Control-C>", copy)
    entry_widget.bind("<Control-x>", cut)
    entry_widget.bind("<Control-X>", cut)
    entry_widget.bind("<Control-v>", paste)
    entry_widget.bind("<Control-V>", paste)

def run_og_viewer(parent=None):
    def search():

        output.config(state="normal")
        device = device_entry.get()
        if not device:
            output.delete("1.0", tk.END)
            output.insert(tk.END, "Введите название устройства.")
            output.config(state="disabled")
        print("device2 is", device)
                    # return
        group = group_entry.get().strip()
        group_entry.delete(0, tk.END)
        group_entry.insert(0, group)

        # if not group:
        #     output.insert(tk.END, "Введите название object-group устройства.")
        #     output.config(state="disabled")
        #     return
        ip = ip_entry.get().strip()

        output.delete("1.0", tk.END)

        parser, objects, err = get_object_group(device, group)

        print("err is", err)
        # print("path2 is", info)
        if err:
            output.insert(tk.END, err)
            output.config(state="disabled")
            return
        # SZSP-DCZK-EXT-FW1_1
        print("group is", group)
        if not group:
            output.insert(tk.END, "Введите название Object-group.")
            output.config(state="disabled")
            return
        if not objects:
            output.insert(tk.END, "Object-group не найден.")
            output.config(state="disabled")
            return
        if not validate_ip_or_network2(ip):
            output.insert(tk.END, "Некорректный формат ip-адреса или сети.")
            output.config(state="disabled")
            return
        # SZSP-DCZK-EXT-FW1_1
        if not ip:
            # if not objects:
            #     output.insert(tk.END, "Object-group не найден.")
            #     output.config(state="disabled")
            #     return
            for obj in objects:
                # print(obj)
                output.insert(tk.END, obj["text"] + "\n")

                # print("3")
            output.config(state="disabled")
            return
        # output.config(state="disabled")
        # ranges = parser.parse_object_ranges()

        result = parser.check_ip(objects, ip)
        # print(result)
        found = False
        for text, match in result:

            # cnt = 0
            # print(match)
            # print(text)
            if match:
                found = True
                # cnt+=1
                # output.insert("1.0", "Найдено совпадений: " +str(cnt) + "\n", )
                output.insert(tk.END, text + "\n", "bold" )
                # output.insert(tk.END, "Found"+"\n")
                # print("1")
                # print("text is",text)
            else:
                output.insert(tk.END, text + "\n")
        if not found:
            output.insert("1.0", "Совпадений не найдено." + "\n", "bold")
        output.config(state="disabled")
                # print("2")
                # print(text)
    def clear():
        device_entry.delete(0, tk.END)
        group_entry.delete(0,tk.END)
        ip_entry.delete(0,tk.END)
        return
    def clear_devs():
        device_entry.delete(0, tk.END)
        return
    def clear_gr():
        group_entry.delete(0, tk.END)
        return
    def clear_ips():
        ip_entry.delete(0, tk.END)
        return



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

    window.bind("<Shift-F1>", lambda e: run_og_viewer())
    window.bind("<Escape>", lambda e: window.destroy())



    tk.Label(frame, text="Устройство:",bg="#f0f0f0").grid(row=0, column=0, sticky="e",padx=(30, 2))
    device_entry = tk.Entry(frame, width=40)
    device_entry.grid(row=0, column=1, sticky = "w", padx = (2,0))
    fix_device_entry(device_entry)

    # --

    # def prevent_leading_space(event):
    #     if event.keysym == 'space':
    #         cursor_pos = group_entry.index(tk.INSERT)  # ← важно использовать group_entry
    #         current = ip_var.get()
    #
    #         # Если курсор в начале и в поле нет нормальных символов
    #         if cursor_pos == 0 and not current.strip():
    #             return 'break'  # полностью блокируем событие
    #
    #     return None

    # === Создание поля ===
    tk.Label(frame, text="Object-group:", bg="#f0f0f0").grid(row=1, column=0, sticky="e", padx=(10, 2))

    group_entry = tk.Entry(frame, width=40)
    group_entry.grid(row=1, column=1, sticky="w", padx=(2, 0))
    fix_entry_shortcuts(group_entry)

    # group_entry.bind('<KeyPress>', prevent_leading_space)

    # group_entry.bind("<FocusOut>", strip_entry)
    # group_entry.bind("<FocusOut>", clean_entry)
    # group_entry.bind("<FocusOut>", strip_whitespace)



    tk.Label(frame, text="IP / Network:",bg="#f0f0f0").grid(row=2, column=0,sticky="e", padx=(10, 2))
    ip_entry = tk.Entry(frame, width=40)
    ip_entry.grid(row=2, column=1, sticky="w", padx=(2, 0))
    fix_entry_shortcuts(ip_entry)

    search_btn = tk.Button(frame, text="Поиск", command=search)
    search_btn.grid(row=3, column=1,sticky="w",padx=120,pady=(4, 4))

    clear_btn = tk.Button(frame, text="del all", command=clear,font=("Arial", 9))
    clear_btn.grid(row=3, column=1,sticky="e",padx=17,pady=(0,20))


    clear_dev_btn = tk.Button(frame, text="del", command=clear_devs,font=("Arial", 8))
    clear_dev_btn.grid(row=0, column=1,sticky="e",padx=35)

    clear_gr_btn = tk.Button(frame, text="del", command=clear_gr,font=("Arial", 8))
    clear_gr_btn.grid(row=1, column=1,sticky="e",padx=35)

    clear_ip_btn = tk.Button(frame, text="del", command=clear_ips,font=("Arial", 8))
    clear_ip_btn.grid(row=2, column=1,sticky="e",padx=35)
    

    output = scrolledtext.ScrolledText(frame, width=63, height=25,takefocus=0)
    output.grid(row=4, column=0, columnspan=2)
    output.config(state="disabled")
    output.tag_config("bold", font=("TkDefaultFont", 10, "bold"))
