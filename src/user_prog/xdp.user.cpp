/*
 * @Author: sunzhenbao && sunzhenbao@live.com
 * @Date: 2023-09-10 22:02:30
 * @LastEditors: sunzhenbao sunzhenbao@live.com
 * @LastEditTime: 2023-09-11 14:45:29
 * @FilePath: /network-filter/src/user_prog/xdp.user.cpp
 * @Description: 
 * 
 * Copyright (c) 2023 by sunzhenbao.live.com, All Rights Reserved.
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "xdp.user.h"

// #include <linux/err.h> /* ERR_PTR */
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "unistd.h"
#include <iostream>

#include "err.h"
#include "utility.h"

long xp_error(const void *ptr)
{
    if (!IS_ERR_OR_NULL(ptr))
        return 0;

    if (IS_ERR(ptr))
        errno = -PTR_ERR(ptr);
    return -errno;
}

int xdp_str_error(int err, char *buf, size_t size)
{
    return libbpf_strerror(err, buf, size);
}

namespace liang
{
    namespace xdp
    {
        XDPProgram::~XDPProgram()
        {
            if (bpf_obj_)
            {
                bpf_object__close(bpf_obj_);
                bpf_obj_ = nullptr;
            }
        }

        long XDPProgram::CreateXDPPrgram(const XDPProgOpts &opts, XDPProgram *out_prog)
        {
            struct bpf_object *bpf_obj{nullptr};
            struct bpf_program *bpf_prog{nullptr};
            int err{0};
            int prog_fd{0};

            // 1. open bpf object file
            bpf_obj = bpf_object__open_file(opts.file_name_.c_str(), NULL);
            if (nullptr == bpf_obj)
            {
                err = errno;
                fprintf(stderr,
                        "open bpf object file failed, filename: %s, errno: %d, errstr: %s\n",
                        opts.file_name_.c_str(),
                        errno,
                        strerror(errno));
                return err;
            }

            // 2. load bpf bytecode program by section,prog name or else using first one.
            if (opts.sec_name_.size() > 0)
            {
                bpf_prog = bpf_program_by_section_name(bpf_obj, opts.sec_name_.c_str());
            }
            else if (opts.prog_name_.size() > 0)
            {
                bpf_prog = bpf_object__find_program_by_name(bpf_obj, opts.prog_name_.c_str());
            }
            else
            {
                bpf_prog = bpf_object__next_program(bpf_obj, NULL);
            }
            if (NULL == bpf_prog)
            {
                err = errno;
                fprintf(stderr, "find program in object failed, (%d)%s\n", errno, strerror(errno));
                goto cleanup;
            }

            // 3. set bpf type
            err = bpf_program__set_type(bpf_prog, BPF_PROG_TYPE_XDP);
            if (err)
            {
                fprintf(stderr, "set bpf to xdp failed, (%d)%s\n", errno, strerror(errno));
                goto cleanup;
            }

            // 4. load object
            err = bpf_object__load(bpf_obj);
            if (err)
            {
                fprintf(stderr, "load bpf object failed: (%d)%s\n", errno, strerror(errno));
                goto cleanup;
            }

            // 5. get bpf fd
            prog_fd = bpf_program__fd(bpf_prog);
            if (!prog_fd)
            {
                fprintf(stderr, "loading BPF-OBJ file(%s) failed, (%d)%s\n", opts.file_name_.c_str(), err, strerror(-err));
                return -1;
            }
            out_prog->file_name_ = opts.file_name_;
            out_prog->prog_name_ = bpf_program__name(bpf_prog);
            out_prog->bpf_prog_ = bpf_prog;
            out_prog->bpf_obj_ = bpf_obj;
            out_prog->bpf_btf_ = bpf_object__btf((const struct bpf_object *)bpf_obj);
            out_prog->prog_type_ = bpf_program__get_type(bpf_prog);
            out_prog->prog_fd_ = prog_fd;

            return 0;

        cleanup:
            if (nullptr != bpf_obj)
            {
                bpf_object__close(bpf_obj);
                bpf_obj = nullptr;
            }
            return errno;
        }

        int XDPProgram::Attach(const XDPAttachMode attach_mode, const Interface &iface, const std::string &pin_root_path)
        {
            static const char *sub_path = "programs";
            // create sub path for pin, sub path's name is "programs"
            auto err = make_dir_subdir(pin_root_path.c_str(), sub_path);
            if (err)
            {
                fprintf(stderr, "create pin path failed, pin path: %s, sub path: %s, err: %d\n",
                        pin_root_path.c_str(), sub_path, err);
                return err;
            }

            // construct the full pin file name
            char pin_path[4096]{0};
            snprintf(pin_path, sizeof(pin_path),
                     "%s/%s/%s/%s", pin_root_path.c_str(),
                     sub_path, iface.if_name_.c_str(),
                     prog_name_.c_str());

            auto xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
            if (XDP_MODE_SKB == attach_mode)
            {
                xdp_flags |= XDP_FLAGS_SKB_MODE;
            }
            else
            {
                xdp_flags |= XDP_FLAGS_DRV_MODE;
            }

            // try to set XDP to interface link
            auto bpf_err = bpf_xdp_attach(iface.if_index_, prog_fd_, xdp_flags, NULL);
            if (bpf_err == -EEXIST)
            {
                // XDP has existed, try to re-attach
                if (!xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)
                {
                    // detach old one
                    uint32_t old_flags = xdp_flags;
                    xdp_flags &= ~XDP_FLAGS_MODES;
                    xdp_flags = (old_flags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
                    if (bpf_xdp_detach(iface.if_index_, xdp_flags, NULL) == 0)
                    {
                        // re-attach
                        std::cout << "try to attach xdp again" << std::endl;
                        bpf_err = bpf_xdp_attach(iface.if_index_, prog_fd_, old_flags, NULL);
                    }
                }
            }

            if (bpf_err < 0)
            {
                // error
                fprintf(stderr, "interface link set xdp fd failed, %s, (%d)%s",
                        iface.if_name_.c_str(),
                        -bpf_err,
                        strerror(-bpf_err));
                switch (-bpf_err)
                {
                case EBUSY:
                case EEXIST:
                    fprintf(stderr, "XPD already loaded on the device: %s\n", iface.if_name_.c_str());
                    break;
                case ENOMEM:
                case EOPNOTSUPP:
                    unlink(pin_path);
                    fprintf(stderr, "native-XDP not supported by the device %s, try --skb-mode\n", iface.if_name_.c_str());
                    break;
                default:
                    unlink(pin_path);
                    fprintf(stderr, "attach unexpected error, err: %d, device: %s", -bpf_err, iface.if_name_.c_str());

                    break;
                }
            }

            std::cout << "program loaded on interface, prog: " << prog_name_.c_str()
                      << ", iface_name: " << iface.if_name_.c_str()
                      << ", attach_mode: " << (attach_mode == XDP_MODE_SKB ? " in skb mode" : "") << std::endl;

            bpf_err = bpf_program__pin(bpf_prog_, pin_path);

            if (bpf_err)
            {
                bpf_xdp_detach(iface.if_index_, xdp_flags, NULL);
                return bpf_err;
            }

            attach_mode_ = attach_mode;
            attached_ = true;
            iface_ = iface;
            pin_path_ = pin_path;

            return 0;
        }

        int XDPProgram::Dettach()
        {
            if (!attached_)
            {
                return 0;
            }

            return bpf_xdp_detach(iface_.if_index_, xdp_flags_, nullptr);
        }

        Interface::Interface(const std::string &name) : if_name_(name),
                                                        if_index_(if_nametoindex(name.c_str()))
        {
        }
    }
}