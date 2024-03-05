/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LOGGER_HPP_
#define LOGGER_HPP_

#include <mutex>

#include <aos/common/tools/log.hpp>

/**
 * Log module type.
 */
class LogModuleType {
public:
    enum class Enum {
        eApp,
        eNumModules,
    };

    static const aos::Array<const char* const> GetStrings()
    {
        static const char* const sLogModuleTypeStrings[] = {
            "app",
        };

        return aos::Array<const char* const>(sLogModuleTypeStrings, aos::ArraySize(sLogModuleTypeStrings));
    };
};

using LogModuleEnum = LogModuleType::Enum;
using LogModule     = aos::EnumStringer<LogModuleType>;

/**
 * Converts IAM LogModuleEnum to aos::LogModuleEnum.
 *
 * @param module IAM log module.
 * @return aos::LogModuleEnum.
 */
constexpr auto AosLogModule(LogModuleEnum module)
{
    return static_cast<aos::LogModuleEnum>(
        static_cast<int>(aos::LogModuleEnum::eNumModules) + static_cast<int>(module));
}

/**
 * Converts aos::LogModuleEnum to IAM LogModuleEnum.
 *
 * @param module Aos log module.
 * @return aos::LogModuleEnum.
 */
constexpr auto IAMLogModule(aos::LogModuleEnum module)
{
    return static_cast<LogModuleEnum>(static_cast<int>(module) - static_cast<int>(aos::LogModuleEnum::eNumModules));
}

/**
 * Logger instance.
 */
class Logger {
public:
    /**
     * Log backends.
     */
    enum class Backend {
        eStdIO,
    };

    /**
     * Initializes logging system.
     *
     * @return aos::Error.
     */
    aos::Error Init();

private:
    static constexpr auto cColorTime    = "\033[90m";
    static constexpr auto cColorDebug   = "\033[37m";
    static constexpr auto cColorInfo    = "\033[32m";
    static constexpr auto cColorWarning = "\033[31m";
    static constexpr auto cColorError   = "\033[31m";
    static constexpr auto cColorUnknown = "\033[36m";
    static constexpr auto cColorModule  = "\033[34m";
    static constexpr auto cColorNone    = "\033[0m";

    static void        StdIOCallback(aos::LogModule module, aos::LogLevel level, const aos::String& message);
    static std::string GetCurrentTime();
    static std::string GetLogLevel(aos::LogLevel level);
    static std::string GetModule(aos::LogModule module);
    static void        SetColored(bool colored) { sColored = colored; }

    static std::mutex sMutex;
    static bool       sColored;
    static Backend    sBackend;
};

#endif
