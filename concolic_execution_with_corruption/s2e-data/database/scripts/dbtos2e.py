import os
import json
import argparse
import subprocess

store_hook_address = 0xffffffff87bb02d0
post_store_hook_address = 0xffffffff87bb0490
asan_memcpy_address = 0xffffffff87bb0540
asan_memmov_address = 0xffffffff87bb04a0
copy_from_user_address = 0xffffffff87bb05e0

base_syzkaller = os.environ["DATA"]+"/reproducers/repro-"

def main ():
    # import json db
    try:
        home = os.environ["S2EDIR"]
    except KeyError:
        print("Error reading S2EDIR")
        exit()

    parser = argparse.ArgumentParser()
    parser.add_argument("filename")
    parser.add_argument("ubts")
    args = parser.parse_args()

    print(args.filename)
    print(args.ubts)

    ubts_f = open(args.ubts)
    f = open(args.filename)

    print("loading json db")
    global pandadb
    pandadb = json.load(f)
    data = pandadb

    print("loading ubts db")

    global ubts_data
    ubts_data = json.load(ubts_f)

    print("parsing values in main db")
    for value in data:
        (valid, parsed_entry) = parse_entry(value)

        if not valid:
            continue

        print (parsed_entry.id)
        print (parsed_entry.kdo_config)
        # continue
        subprocess.run(["s2e" , "new_project" , "--debootstrap" , "-t" , \
                        "linux", "-i" , "buildroot-6.4.1" , "-n" , parsed_entry.id, "{}{}".format(base_syzkaller, parsed_entry.id)])
        subprocess.run(["ln", "-s", os.environ["DATA"]+"/s2e-kprobe/s2e-6.4.1/s2e-kprobe.ko", "{}/projects/{}/".format(home, parsed_entry.id)])
        save_db_entry(parsed_entry.id)
        # subprocess.run(["python3", "/home/s2e/data/database/scripts/extract-entry.py", "/home/s2e/data/database/panda.data", parsed_entry.id])
        # subprocess.run(["mv", "{}.output".format(parsed_entry.id), "{}/projects/{}/".format(home, parsed_entry.id)])

        f = open("{}/projects/{}/s2e-config.lua".format(home,parsed_entry.id), "a")
        f.write("-- ")
        f.write(parsed_entry.id)
        f.write("\n")
        f.write(parsed_entry.kdo_config)
        f.close()

#s2e new_project --debootstrap -t linux -i jammy-6.8-rc1 -n 6e675f56f166258c81bc8343ed6b2207f05a00e6 /home/mbr/work/repositories/kdo/kdo_syzkaller_res/13/repros/repro-6e675f56f166258c81bc8343ed6b2207f05a00e6
def save_db_entry(item_id):
    for entry in pandadb:
        for key, val in entry.items():
            if key == "id":
                if val.startswith(item_id):
                    out = open("/home/s2e/cco_s2e/projects/{}/{}.{}".format(item_id, item_id, "output"), "w")
                    json.dump(entry, out, indent=4)
                    out.close()
                    return


def parse_replay(entry):
    if entry.get("err") == "no_memcpy":
        print("Error no memcpy entry - quitting")
        return (None, (None,None,None,None), (None, None, None), {}, -1, None)
    try:
        dst_ptr_alloc = entry['dst_ptr_alloc']
        counterfeit_data_size = parse_dst_ptr(dst_ptr_alloc)
    except KeyError:
        counterfeit_data_size = None

    try:
        ptr_ass = entry['ptr_ass']
        ptr_ass_res = parse_ptr_ass(ptr_ass)
    except KeyError:
        ptr_ass_res = (None, None, None, None)

    try:
        sink = entry['sink']
        sink_res = parse_sink(sink)
    except KeyError:
        sink_res = (None, None, None)
        print("Field sink not available")

    try:
        taint = entry.get("taint_src")
        if taint == None:
            print("Missing taint_src entry - quitting ")
            return (None, (None,None,None,None), (None, None, None), {}, -1, None)

        taint_res = parse_taint_src(taint)
    except KeyError as ke:
        taint_res = {}
        print("Error parsing taint_src {}".format(ke))

    try:
        memop_ctr = entry['memcpy_ctr']-1
    except KeyError:
        memop_ctr = -1

    try:
        target_object_entry = entry.get("target_obj_alloc")

        if (target_object_entry is not None):
            target_object_ptr = target_object_entry.get("ptr")
        else:
            target_object_ptr = None
    except KeyError:
        target_object_ptr = None

    return (counterfeit_data_size, ptr_ass_res, \
    sink_res, taint_res, memop_ctr, target_object_ptr)


def parse_taint_src(entry):
    cfu_id_set_counter = {}
    for el in entry:
        if el.get("err") == "no_taint":
            continue
        for i in el['data']:
            if i['cfu_id'] not in cfu_id_set_counter:
                cfu_id_set_counter[i['cfu_id']] = set()

            cfu_id_set_counter[i['cfu_id']].add(int(i['ctr']))
    return cfu_id_set_counter

def parse_sink(entry):
    ubts_id = entry['syscall']['u_bt']
    #entry['syscall']['backtrace'][0]['caller_off']
    return (entry['call_id'], entry['syscall']['global_ctr'], ubts_data[str(ubts_id)]['backtrace'][0]['caller_off'])

def parse_dst_ptr(entry):
    return  entry['size']

def parse_ptr_ass(entry):
    try:
        dst_ptr = None
        dst_ptr = entry["dst_ptr"]
    except KeyError:
        dst_ptr = None

    print("dst_ptr = {}".format(dst_ptr))

    return (entry['call_id'], entry['syscall']['global_ctr'], entry['ctr'], dst_ptr)


class Entry:
    def __init__(self):
        self.id = 0
        self.store_type = ""
        self.fname = ""
        self.kdo_config = ""
        self.syscall = ""

    def set_id(self, id):
        self.id = id

    def set_store_type(self, store_type):
        self.store_type = store_type

    def set_fname(self, fname):
        self.fname = fname

    def set_kdo_config(self, kdo_config):
        self.kdo_config = kdo_config




def parse_entry(entry):
    sink_global_ctr = None
    ptr_ass_global_ctr = None
    target_object_offset = -1
    p = Entry()
    for key, val in entry.items():
        if key == "id":
            p.id = val
            print("Reproducer =", val)

        if key == "store_type":
            p.store_type = val
            print("Store type = ", val)

        if key == "fname":
            p.fname = val
            # print("name = ", val)

        if key == "replay":
            (counterfeit_data_size, \
             (ptr_ass_call_id, ptr_ass_global_ctr, ptr_ass_ctr, dst_ptr), \
             (sink_call_id, sink_global_ctr, caller_off),
             cfu_id_list, memop_ctr, target_object_ptr) = parse_replay(val)
            print("cfu_id_list {}".format(cfu_id_list))

            if (dst_ptr is not None and target_object_ptr is not None):
                target_object_offset = dst_ptr - target_object_ptr

                if (target_object_offset > 0x2000):
                    print("Error object offset too big defaulting to -1")
                    target_object_offset = -1
            else:
                target_object_offset = -1

        if key == "joern_analysis":
            try:
                p.store_type = val["store_type"]
            except KeyError:
                p.store_type = "None"

    if sink_global_ctr is None or ptr_ass_global_ctr is None:
        print("Skipping")
        # print ("sink_global_ctr = ", sink_global_ctr)
        # print ("ptr_ass_global_ctr = ", ptr_ass_global_ctr)
        return (False, None)

    if (sink_global_ctr != ptr_ass_global_ctr):
        p.syscall = "different"
    else:
        p.syscall = "same"

    # if p.syscall == "different":
    final_string = """
add_plugin("kdo")
pluginsConfig.kdo = {{
    symbolic = true,
    kdo_id = "{id}",
    kdo_store_hook_callid = {store_hook_callid},
    kdo_store_hook_addr = {store_hook_addr},
    kdo_post_store_hook_addr = {post_store_hook_addr},
    kdo_store_ctr = {store_hook_ctr},

    kdo_asan_memop_callid = {asan_memop_callid},
    kdo_asan_memcpy_addr = {asan_memcpy_addr},
    kdo_asan_memmov_addr = {asan_memmov_addr},
    kdo_asan_memop_ctr = {memop_ctr},

    kdo_copy_from_user_addr = {copy_from_user_addr},

    kdo_counterfeit_data_size = {counterfeit_object_size},

    kdo_target_object_offset = {target_object_offset},

    kdo_corruption_location = {corruption_location},

    kdo_memop_type = "{memop_type}",

    kdo_syscall_type = "{syscall_type}",

    kdo_fork_state = false,

    kdo_cfu_id_list = {{
        {cfu_id_list_str}
    }},

    {cfu_id_ctr},

    filter_addr_start = {{
        0xffffffff81b2bf80, --____kasan_kfree_large
        0xffffffff81b2bde0, --____kasan_slab_free
        0xffffffff81b2c4a0, --__kasan_check_byte
        0xffffffff81b2eeb0, --__kasan_check_read
        0xffffffff81b2eed0, --__kasan_check_write
        0xffffffff81b2bdb0, --__kasan_init_slab_obj
        0xffffffff81b2bf80, --____kasan_kfree_large
        0xffffffff81b2bee0, --__kasan_kfree_large
        0xffffffff81b2c2a0, --__kasan_kmalloc
        0xffffffff81b2c330, --__kasan_kmalloc_large
        0xffffffff81b2c330, --__kasan_kmalloc_large
        0xffffffff81b2c3d0, --__kasan_krealloc
        0xffffffff81b2bd90, --__kasan_poison_object_data
        0xffffffff81b2bcb0, --__kasan_poison_pages
        0xffffffff81b2bce0, --__kasan_poison_slab
        0xffffffff81b2f690, --__kasan_poison_vmalloc
        0xffffffff81b2c240, --__kasan_slab_alloc
        0xffffffff81b2bde0, --____kasan_slab_free
        0xffffffff81b2c020, --__kasan_slab_free_mempool
        0xffffffff81b2bdd0, --__kasan_slab_free
        0xffffffff81b2c020, --__kasan_slab_free_mempool
        0xffffffff81b2bd70, --__kasan_unpoison_object_data
        0xffffffff81b2bd50, --__kasan_unpoison_object_data_default
        0xffffffff81b2bd50, --__kasan_unpoison_object_data_default
        0xffffffff81b2bc80, --__kasan_unpoison_pages
        0xffffffff81b2bc50, --__kasan_unpoison_pages_default
        0xffffffff81b2bc50, --__kasan_unpoison_pages_default
        0xffffffff81b2bbf0, --__kasan_unpoison_range_default
        0xffffffff81b2bc00, --__kasan_unpoison_range
        0xffffffff81b2bbf0, --__kasan_unpoison_range_default
        0xffffffff81b2f610, --__kasan_unpoison_vmalloc
        0xffffffff87bb0540, --__kdo_asan_memcpy
        0xffffffff87bb04a0, --__kdo_asan_memmove
        0xffffffff8c9f4a30, --early_kasan_fault
        0xffffffff81b2d6f0, --kasan_add_zero_shadow
        0xffffffff81b2ba20, --kasan_addr_to_slab
        0xffffffff81b2db60, --kasan_byte_accessible
        0xffffffff81b2e320, --kasan_cache_create
        0xffffffff81b2db90, --kasan_cache_shrink
        0xffffffff81b2dba0, --kasan_cache_shutdown
        0xffffffff81b2d740, --kasan_check_range
        0xffffffff81b2e6f0, --kasan_complete_mode_report_info
        0xffffffff81b301e0, --kasan_cpu_offline
        0xffffffff81b301c0, --kasan_cpu_online
        0xffffffff8c9f4b40, --kasan_cpu_quarantine_init
        0xffffffff81b2f590, --kasan_depopulate_vmalloc_pte
        0xffffffff81b2bbd0, --kasan_disable_current
        0xffffffff8c9ba5e0, --kasan_early_init
        0xffffffff81b2bbb0, --kasan_enable_current
        0xffffffff81b2e650, --kasan_find_first_bad_addr
        0xffffffff81b2e400, --kasan_get_alloc_meta
        0xffffffff81b2e6a0, --kasan_get_alloc_size
        0xffffffff81b2e420, --kasan_get_free_meta
        0xffffffff8c9ba960, --kasan_init
        0xffffffff81b2bdb0, --__kasan_init_slab_obj
        0xffffffff81b2e440, --kasan_init_object_meta
        0xffffffff81b2e440, --kasan_init_object_meta
        0xffffffff8c9ba700, --kasan_map_early_shadow
        0xffffffff87c52620, --kasan_mem_notifier
        0xffffffff8c9f4b10, --kasan_memhotplug_init
        0xffffffff81b2e900, --kasan_metadata_fetch_row
        0xffffffff81b2e470, --kasan_metadata_size
        0xffffffff81b2e310, --kasan_never_merge
        0xffffffff81b2bcb0, --__kasan_poison_pages
        0xffffffff81b2f690, --__kasan_poison_vmalloc
        0xffffffff81b2bce0, --__kasan_poison_slab
        0xffffffff81b2bd90, --__kasan_poison_object_data
        0xffffffff81b2f010, --kasan_poison
        0xffffffff81b2f060, --kasan_poison_last_granule
        0xffffffff81b2f060, --kasan_poison_last_granule
        0xffffffff87bda1c0, --kasan_populate_early_shadow
        0xffffffff8c9f4b30, --kasan_populate_early_vm_area_shadow
        0xffffffff8c9bacd0, --kasan_populate_p4d
        0xffffffff8c9bb050, --kasan_populate_pmd
        0xffffffff8c9bae20, --kasan_populate_pud
        0xffffffff8c9ba890, --kasan_populate_shadow
        0xffffffff8c9ba830, --kasan_populate_shadow_for_vaddr
        0xffffffff8c9ba830, --kasan_populate_shadow_for_vaddr
        0xffffffff81b2f1e0, --kasan_populate_vmalloc_pte
        0xffffffff81b2f170, --kasan_populate_vmalloc
        0xffffffff81b2f1e0, --kasan_populate_vmalloc_pte
        0xffffffff81b2f340, --kasan_populate_vmemmap_pte
        0xffffffff81b2f2e0, --kasan_populate_vmemmap
        0xffffffff81b2f340, --kasan_populate_vmemmap_pte
        0xffffffff81b2e9a0, --kasan_print_address_stack_frame
        0xffffffff81b2e930, --kasan_print_aux_stacks
        0xffffffff81b2f780, --kasan_quarantine_put
        0xffffffff81b2f9b0, --kasan_quarantine_reduce
        0xffffffff81b2fbd0, --kasan_quarantine_remove_cache
        0xffffffff81b2e560, --kasan_record_aux_stack_noalloc
        0xffffffff81b2e4c0, --kasan_record_aux_stack
        0xffffffff81b2e560, --kasan_record_aux_stack_noalloc
        0xffffffff81b2f4e0, --kasan_release_vmalloc
        0xffffffff81b2cf50, --kasan_remove_zero_shadow
        0xffffffff81b2c4e0, --kasan_report_invalid_free
        0xffffffff81b2cda0, --kasan_report
        0xffffffff81b2cd10, --kdo_kasan_report
        0xffffffff81b2c4e0, --kasan_report_invalid_free
        0xffffffff81b2e5f0, --kasan_save_alloc_info
        0xffffffff81b2e610, --kasan_save_free_info
        0xffffffff81b2bae0, --kasan_save_stack
        0xffffffff8c9f4a80, --kasan_set_multi_shot
        0xffffffff81b2bb40, --kasan_set_track
        0xffffffff8c9bb330, --kasan_shallow_populate_p4ds
        0xffffffff81b2bc10, --kasan_unpoison_task_stack
        0xffffffff81b2bc30, --kasan_unpoison_task_stack_below
        0xffffffff81b2bbf0, --__kasan_unpoison_range_default
        0xffffffff81b2bc00, --__kasan_unpoison_range
        0xffffffff81b2bc80, --__kasan_unpoison_pages
        0xffffffff81b2f610, --__kasan_unpoison_vmalloc
        0xffffffff81b2bc50, --__kasan_unpoison_pages_default
        0xffffffff81b2bd70, --__kasan_unpoison_object_data
        0xffffffff81b2f090, --kasan_unpoison_default
        0xffffffff81b2f100, --kasan_unpoison
        0xffffffff81b2bd50, --__kasan_unpoison_object_data_default
        0xffffffff81b2f090, --kasan_unpoison_default
        0xffffffff81b2bc10, --kasan_unpoison_task_stack
        0xffffffff81b2bc30, --kasan_unpoison_task_stack_below
        0xffffffff81b2bc30, --kasan_unpoison_task_stack_below
        0xffffffff87bb05e0, --kdo_copy_from_user
        0xffffffff87bafef0, --kdo_get_user
        0xffffffff87bb06d0, --kdo_init
        0xffffffff81b2cd10, --kdo_kasan_report
        0xffffffff81b2cd10, --kdo_kasan_report
        0xffffffff87bb0490, --kdo_post_store_hook
        0xffffffff87bb11e0, --kdo_sanitizer_cov_init
        0xffffffff87bb1250, --kdo_sanitizer_cov_read
        0xffffffff87bb1160, --kdo_sanitizer_cov_trace_copy_from_user
        0xffffffff87bb10e0, --kdo_sanitizer_cov_trace_memintrinsic
        0xffffffff87bb1060, --kdo_sanitizer_cov_trace_store
        0xffffffff87bb1270, --kdo_sanitizer_cov_write
        0xffffffff87baff00, --kdo_set_storedonheap
        0xffffffff87bb02d0, --kdo_store_hook
        0xffffffff87baff70, --kdo_taint_val_stored_on_heap
    }},
    filter_addr_end = {{
        0xffffffff81b2c015, --____kasan_kfree_large
        0xffffffff81b2bed3, --____kasan_slab_free
        0xffffffff81b2c4d4, --__kasan_check_byte
        0xffffffff81b2eec1, --__kasan_check_read
        0xffffffff81b2eee4, --__kasan_check_write
        0xffffffff81b2bdc2, --__kasan_init_slab_obj
        0xffffffff81b2c015, --____kasan_kfree_large
        0xffffffff81b2bf76, --__kasan_kfree_large
        0xffffffff81b2c327, --__kasan_kmalloc
        0xffffffff81b2c3cb, --__kasan_kmalloc_large
        0xffffffff81b2c3cb, --__kasan_kmalloc_large
        0xffffffff81b2c49b, --__kasan_krealloc
        0xffffffff81b2bdb0, --__kasan_poison_object_data
        0xffffffff81b2bcdd, --__kasan_poison_pages
        0xffffffff81b2bd41, --__kasan_poison_slab
        0xffffffff81b2f6e8, --__kasan_poison_vmalloc
        0xffffffff81b2c29a, --__kasan_slab_alloc
        0xffffffff81b2bed3, --____kasan_slab_free
        0xffffffff81b2c1dc, --__kasan_slab_free_mempool
        0xffffffff81b2bdde, --__kasan_slab_free
        0xffffffff81b2c1dc, --__kasan_slab_free_mempool
        0xffffffff81b2bd86, --__kasan_unpoison_object_data
        0xffffffff81b2bd64, --__kasan_unpoison_object_data_default
        0xffffffff81b2bd64, --__kasan_unpoison_object_data_default
        0xffffffff81b2bcab, --__kasan_unpoison_pages
        0xffffffff81b2bc79, --__kasan_unpoison_pages_default
        0xffffffff81b2bc79, --__kasan_unpoison_pages_default
        0xffffffff81b2bbfb, --__kasan_unpoison_range_default
        0xffffffff81b2bc0d, --__kasan_unpoison_range
        0xffffffff81b2bbfb, --__kasan_unpoison_range_default
        0xffffffff81b2f683, --__kasan_unpoison_vmalloc
        0xffffffff87bb05d6, --__kdo_asan_memcpy
        0xffffffff87bb0536, --__kdo_asan_memmove
        0xffffffff8c9f4a7f, --early_kasan_fault
        0xffffffff81b2d738, --kasan_add_zero_shadow
        0xffffffff81b2ba3b, --kasan_addr_to_slab
        0xffffffff81b2db89, --kasan_byte_accessible
        0xffffffff81b2e3f8, --kasan_cache_create
        0xffffffff81b2db99, --kasan_cache_shrink
        0xffffffff81b2dbbc, --kasan_cache_shutdown
        0xffffffff81b2db5b, --kasan_check_range
        0xffffffff81b2e8f2, --kasan_complete_mode_report_info
        0xffffffff81b3024f, --kasan_cpu_offline
        0xffffffff81b301dd, --kasan_cpu_online
        0xffffffff8c9f4b86, --kasan_cpu_quarantine_init
        0xffffffff81b2f610, --kasan_depopulate_vmalloc_pte
        0xffffffff81b2bbe3, --kasan_disable_current
        0xffffffff8c9ba6f6, --kasan_early_init
        0xffffffff81b2bbc3, --kasan_enable_current
        0xffffffff81b2e696, --kasan_find_first_bad_addr
        0xffffffff81b2e417, --kasan_get_alloc_meta
        0xffffffff81b2e6e4, --kasan_get_alloc_size
        0xffffffff81b2e43d, --kasan_get_free_meta
        0xffffffff8c9babeb, --kasan_init
        0xffffffff81b2bdc2, --__kasan_init_slab_obj
        0xffffffff81b2e465, --kasan_init_object_meta
        0xffffffff81b2e465, --kasan_init_object_meta
        0xffffffff8c9ba821, --kasan_map_early_shadow
        0xffffffff87c5281e, --kasan_mem_notifier
        0xffffffff8c9f4b23, --kasan_memhotplug_init
        0xffffffff81b2e923, --kasan_metadata_fetch_row
        0xffffffff81b2e4bb, --kasan_metadata_size
        0xffffffff81b2e31a, --kasan_never_merge
        0xffffffff81b2bcdd, --__kasan_poison_pages
        0xffffffff81b2f6e8, --__kasan_poison_vmalloc
        0xffffffff81b2bd41, --__kasan_poison_slab
        0xffffffff81b2bdb0, --__kasan_poison_object_data
        0xffffffff81b2f056, --kasan_poison
        0xffffffff81b2f082, --kasan_poison_last_granule
        0xffffffff81b2f082, --kasan_poison_last_granule
        0xffffffff87bda392, --kasan_populate_early_shadow
        0xffffffff8c9f4b35, --kasan_populate_early_vm_area_shadow
        0xffffffff8c9bae1d, --kasan_populate_p4d
        0xffffffff8c9bb330, --kasan_populate_pmd
        0xffffffff8c9bb04b, --kasan_populate_pud
        0xffffffff8c9ba954, --kasan_populate_shadow
        0xffffffff8c9ba888, --kasan_populate_shadow_for_vaddr
        0xffffffff8c9ba888, --kasan_populate_shadow_for_vaddr
        0xffffffff81b2f2d2, --kasan_populate_vmalloc_pte
        0xffffffff81b2f1de, --kasan_populate_vmalloc
        0xffffffff81b2f2d2, --kasan_populate_vmalloc_pte
        0xffffffff81b2f4d5, --kasan_populate_vmemmap_pte
        0xffffffff81b2f331, --kasan_populate_vmemmap
        0xffffffff81b2f4d5, --kasan_populate_vmemmap_pte
        0xffffffff81b2ec88, --kasan_print_address_stack_frame
        0xffffffff81b2e997, --kasan_print_aux_stacks
        0xffffffff81b2f9a1, --kasan_quarantine_put
        0xffffffff81b2fb0f, --kasan_quarantine_reduce
        0xffffffff81b2fef6, --kasan_quarantine_remove_cache
        0xffffffff81b2e5ee, --kasan_record_aux_stack_noalloc
        0xffffffff81b2e551, --kasan_record_aux_stack
        0xffffffff81b2e5ee, --kasan_record_aux_stack_noalloc
        0xffffffff81b2f58c, --kasan_release_vmalloc
        0xffffffff81b2d6ed, --kasan_remove_zero_shadow
        0xffffffff81b2c5df, --kasan_report_invalid_free
        0xffffffff81b2cf42, --kasan_report
        0xffffffff81b2cd95, --kdo_kasan_report
        0xffffffff81b2c5df, --kasan_report_invalid_free
        0xffffffff81b2e610, --kasan_save_alloc_info
        0xffffffff81b2e64f, --kasan_save_free_info
        0xffffffff81b2bb3a, --kasan_save_stack
        0xffffffff8c9f4a92, --kasan_set_multi_shot
        0xffffffff81b2bbaf, --kasan_set_track
        0xffffffff8c9bb3a1, --kasan_shallow_populate_p4ds
        0xffffffff81b2bc24, --kasan_unpoison_task_stack
        0xffffffff81b2bc4b, --kasan_unpoison_task_stack_below
        0xffffffff81b2bbfb, --__kasan_unpoison_range_default
        0xffffffff81b2bc0d, --__kasan_unpoison_range
        0xffffffff81b2bcab, --__kasan_unpoison_pages
        0xffffffff81b2f683, --__kasan_unpoison_vmalloc
        0xffffffff81b2bc79, --__kasan_unpoison_pages_default
        0xffffffff81b2bd86, --__kasan_unpoison_object_data
        0xffffffff81b2f0f4, --kasan_unpoison_default
        0xffffffff81b2f165, --kasan_unpoison
        0xffffffff81b2bd64, --__kasan_unpoison_object_data_default
        0xffffffff81b2f0f4, --kasan_unpoison_default
        0xffffffff81b2bc24, --kasan_unpoison_task_stack
        0xffffffff81b2bc4b, --kasan_unpoison_task_stack_below
        0xffffffff81b2bc4b, --kasan_unpoison_task_stack_below
        0xffffffff87bb06c4, --kdo_copy_from_user
        0xffffffff87bafef6, --kdo_get_user
        0xffffffff87bb06f7, --kdo_init
        0xffffffff81b2cd95, --kdo_kasan_report
        0xffffffff81b2cd95, --kdo_kasan_report
        0xffffffff87bb0496, --kdo_post_store_hook
        0xffffffff87bb1249, --kdo_sanitizer_cov_init
        0xffffffff87bb1266, --kdo_sanitizer_cov_read
        0xffffffff87bb11d2, --kdo_sanitizer_cov_trace_copy_from_user
        0xffffffff87bb1152, --kdo_sanitizer_cov_trace_memintrinsic
        0xffffffff87bb10d2, --kdo_sanitizer_cov_trace_store
        0xffffffff87bb1363, --kdo_sanitizer_cov_write
        0xffffffff87baff65, --kdo_set_storedonheap
        0xffffffff87bb048d, --kdo_store_hook
        0xffffffff87bb00c0, --kdo_taint_val_stored_on_heap
    }},
}}
    """.format(store_hook_callid=ptr_ass_call_id, \
                store_hook_addr=hex(store_hook_address), \
                post_store_hook_addr=hex(post_store_hook_address), \
                asan_memop_callid=sink_call_id, \
                asan_memcpy_addr=hex(asan_memcpy_address), \
                copy_from_user_addr=hex(copy_from_user_address), \
                counterfeit_object_size=counterfeit_data_size, \
                corruption_location=hex(caller_off), \
                cfu_id_list_str=",\n\t".join(str(item) for item in cfu_id_list.keys()), \
                cfu_id_ctr=",\n".join(f"[{key}]={value}" for key, value in cfu_id_list.items()) if len(cfu_id_list) else "placeholder = 0x0", \
                store_hook_ctr = ptr_ass_ctr, \
                memop_ctr = memop_ctr, \
                memop_type = p.store_type,\
                syscall_type = p.syscall,\
                id = p.id, \
                asan_memmov_addr=hex(asan_memmov_address),\
                target_object_offset = hex(target_object_offset))

    p.set_kdo_config(final_string)

    return  (True, p)
    # else:
        # print("global_ctr indicates same syscall")
        # return (False, None)

if __name__ == "__main__":
    main()



