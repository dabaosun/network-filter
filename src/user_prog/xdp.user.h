/*
 * @Author: sunzhenbao && sunzhenbao@live.com
 * @Date: 2023-09-10 22:02:30
 * @LastEditors: sunzhenbao sunzhenbao@live.com
 * @LastEditTime: 2023-09-11 14:45:36
 * @FilePath: /network-filter/src/user_prog/xdp.user.h
 * @Description: 
 * 
 * Copyright (c) 2023 by sunzhenbao.live.com, All Rights Reserved.
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <string>
#include <memory>
#include <ostream>
#include <atomic>

struct bpf_object;
struct bpf_program;
struct btf;

#ifndef DEFAULT_PIN_PATH
#define DEFAULT_PIN_PATH "/sys/fs/bpf/xdp-filter"
#endif

long xp_error(const void *ptr);
int xdp_str_error(int err, char *buf, size_t size);

namespace liang
{
    namespace xdp
    {
        // attach mode,  native / sk_buffer / hardware
        // depends on the ifeth's drive supported or not.
        typedef enum XDPAttachMode
        {
            XDP_MODE_UNSPEC = 0,
            XDP_MODE_NATIVE,
            XDP_MODE_SKB,
            XDP_MODE_HW
        } XDPAttachMode;

        typedef struct Interface
        {
            Interface(const std::string &name);
            std::string if_name_;
            int if_index_;
        } Interface;

        typedef struct XDPProgOpts
        {
            std::string file_name_;
            std::string sec_name_;
            std::string prog_name_;
        } XDPProgOpts;

        class XDPProgram;
        typedef std::unique_ptr<XDPProgram> XDPProgramPtr;

        class XDPProgram
        {
        public:
            ~XDPProgram();

            static long CreateXDPPrgram(const XDPProgOpts &prog_opts, XDPProgram *out_prog);

            int Attach(const XDPAttachMode attach_mode, const Interface &iface, const std::string &pin_path = DEFAULT_PIN_PATH);

            int Dettach();

        public:
            std::string FileName() const
            {
                return file_name_;
            }

            std::string ProgName() const
            {
                return prog_name_;
            }

            std::string SecName() const
            {
                return sec_name_;
            }

            int ProgID() const
            {
                return prog_fd_;
            }

        public:
            friend std::ostream &operator<<(std::ostream &os, const XDPProgram &xdp_prog)
            {
                os << xdp_prog.file_name_.c_str();
                return os;
            }

        private:
            std::string file_name_{""};
            std::string prog_name_{""};
            std::string sec_name_{""};
            bpf_object *bpf_obj_{nullptr};
            bpf_program *bpf_prog_{nullptr};
            struct btf *bpf_btf_{nullptr};
            int prog_type_{0};
            int prog_fd_{0};
            XDPAttachMode attach_mode_{XDP_MODE_UNSPEC};
            bool attached_{false};
            Interface iface_{""};
            int xdp_flags_{0};
            std::string pin_path_{""};

        };
    }
}
