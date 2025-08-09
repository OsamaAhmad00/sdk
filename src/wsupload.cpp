#define _POSIX_SOURCE
#define _LARGE_FILES
#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE 1
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <memory.h>
#include <arpa/inet.h>

#include <iostream>
#include <string>
#include <memory>
#include <thread>
#include <chrono>
#include <mutex>
#include <vector>
#include <list>
#include <set>
#include <unordered_set>
#include <map>
#include <unordered_map>
#include <cassert>

#include <curl/curl.h>

// (for CRC32 - ensure that this is fast!)
#include <zlib.h>

// WebSocket batch file uploading - prototype for SDK integration

// Design goals:

// 1. Instead of unidirectional HTTP POST/response ping-pong communication,
//    harness the power of a full duplex connection (as provided by WebSockets)
// 2. Continuously send at full speed, seamlessly spanning queued files back-to-back.
//    This replaces sending a large block of data and waiting for the server's response.
// 3. No large send buffers - the maximum read-ahead per connection is one chunk
// 4. When a connection is lost, only unconfirmed chunks have to be resent.
//    This is more efficient than having to resend the entire (large) block
//    with HTTP POST scenario, devoid of interim feedback.
// 5. Servers under write pressure can signal uploading clients in real time that
//    they should lower their send rate.
// 6. Servers running out of disk space can signal uploading clients that they
//    should obtain fresh target URLs from the API for subsequent files (otherwise,
//    target URLs are only updated every 24 hours)
// 7. Locally computed MAC must match the file on the server, even if resent data
//    chunks change before resends.

// Architecture:
//
// (The core logic is a 1:1 port of the equivalent webclient functionality.
// Any changes MUST be applied to both versions!)
//
// A WebSocket-supporting version of libcurl is required.
//
// For scalability on devices with high network throughput to CPU core speed ratio,
// a multi-threaded architecture has been chosen, with one thread per WebSocket
// connection doing data reading, encryption/MAC and sending.
//
// A global mutex is kept locked by all relevant threads at all times except when
// sleeping, executing lengthy network or disk I/O, or encrypting. This includes
// the application's main thread! See the supplied main() function for how this works.
//
// When in WebSocket mode, libcurl's curl_multi_wait/curl_multi_poll do not wait
// for handle writability or readability. Until this is fixed (or worked around),
// each thread essentially busy loops (with short sleeps).
//
// WsUploadMgr contains application-facing methods and must be instantiated
// as a permanent global object named g_WsUploadMgr (which is also used internally
// by the implementation).
//
// Upon instantiation, it will launch a thread that will keep running until the
// app quits.
//
// It will immediately query the API for the current file size classes and an
// upload URL for each of them (FIXME: Make the API return the servers' IP
// addresses to skip lengthy DNS lookups). Currently, the size classes are < 1 MB
// (which go to SSD servers) and >= 1 MB (which go to HDD servers).
//
// These upload URLs will be subsequently be used for *all* uploads until the
// logic refreshes them, which happens when
// 1) they are older than 24 hours,
// 2) they are no longer accessible, or
// 3) the server directs the client to refresh
//
// Even if new upload URLs are activated, ongoing uploads to the old ones will
// continue and complete (unless the server has gone down, in which case they
// will be abandoned after trying for four times the elapsed time plus three
// minutes).
//
// To reduce upload start latency, one connection per size class is always kept
// open, even if no upload is queued.
//
// Upload ordering: The upload queue is a std::list. Files will be uploaded
// starting from the beginning. Pools pick the next file according to their
// supported size class, so if you are uploading a mix of big and small files,
// they won't be uploaded in strict order.

// FIXMEs:

// 1. This reference implementation does not contain any code to encrypt/MAC.
//    Please leverage the existing SDK framework.
// 2. This version contains a no-frills API client for the usc command.
//    Use the SDK's non-locking command API channel instead (which should also
//    provide exponential backoff).
// 3. Integrate the SDK's other requirements (filesystem abstraction, thumbnail
//    generation, dynamically adding/removing files from the upload queue,
//    upload throughput display, pausing/unpausing per file and globally,
//    logging, dynamically setting the number of upload connections, etc. pp.)

// IMPROVEMENTS OVER WEBCLIENT, TO BE BACKPORTED:
//
// Heed server's "pause for n ms" command (opcode 6)
// Observe server's "this chunk completes the upload" confirmation (opcode 7)

static const int MB = 1048576;

typedef unsigned __int128 mac_t;

typedef std::list<struct WsUploadFile*> file_list;

// returns the size of a chunk, given its position
struct ChunkMap
{
    static const int SEGSIZE = 131072;

    std::map<off_t, int> chunkmap;

    // must be on a chunk boundary
    int chunksize(off_t pos)
    {
        auto it = chunkmap.find(pos);
        if (it == chunkmap.end()) return 8 * SEGSIZE;
        return it->second;
    }

    ChunkMap()
    {
        off_t p {0};
        unsigned dp {0};

        while (dp < 8 * SEGSIZE)
        {
            dp = dp + SEGSIZE;
            chunkmap[p] = dp;
            p += dp;
        }
    }
} g_chunkMap;

// we want correct MACs and fingerprints even in pathological corner cases
// (a file may be changing during upload, the server may confirm the most recent or an earlier (re)sent chunk...)

struct CRC32
{
    // FIXME: check fastest option, e.g. https://github.com/stbrumme/crc32
    static uint32_t crc32b(const char* data, int len, uint32_t crc = 0)
    {
        // (use zlib)
        return crc32(crc, (const Bytef*)data, len);
/* (the code below is way too slow)
        int i, j;

        crc = ~crc;

        for (i = 0; i < len; i++)
        {
            crc = crc ^ (unsigned char)data[i];

            for (j = 8; j--; ) crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }

        return ~crc;
*/
    }
};

// sparse fingerprint as per MEGA spec
// FIXME: verify correctness
struct FileFingerprint
{
    static const int CRC_SIZE = 16;
    static const int BLOCK_SIZE = CRC_SIZE * 4;
    static const int NUM_BLOCKS = 8192 / BLOCK_SIZE;
    static const int SLICES = 4;

    char data[NUM_BLOCKS * BLOCK_SIZE] {};

    static void extractSparseData(off_t pos, const char* buf, int len, off_t filesize, std::vector<std::pair<short, std::string>>& pieces)
    {
        if (filesize <= (off_t)sizeof data)
        {
            pieces.push_back({ pos, std::string(buf, len) });
        }
        else
        {
            // sparse CRC: assemble relevant file regions in data[]

            // calculate block range covered by [pos, pos+len[
            int startblock = (pos * NUM_BLOCKS -1) / filesize;
            int endblock = ((pos + len) * NUM_BLOCKS -1) / filesize;

            // iterate over block range, compute file offsets, copy sample overlap (if any)
            for (int block = startblock; block <= endblock; block++)
            {
                off_t blockpos = (filesize - BLOCK_SIZE) * block / (NUM_BLOCKS - 1);

                off_t startpos = std::max(pos, blockpos);
                off_t endpos = std::min(pos + len, blockpos + BLOCK_SIZE);

                if (endpos > startpos)
                {
                    pieces.push_back({ block * BLOCK_SIZE + startpos - blockpos, std::string(buf + startpos - pos, endpos - startpos) });
                }
            }
        }
    }

    // write the sparse data pieces for this block to data
    void apply(std::vector<std::pair<short, std::string>>& pieces)
    {
        for (int i = pieces.size(); i--; )
        {
            memcpy(data + pieces[i].first, pieces[i].second.data(), pieces[i].second.size());
        }
    }

    // WARNING: the following code DOES NOT WORK on big-endian CPUs!
    void get(off_t filesize, time_t mtime, std::string& fingerprint)
    {
        assert(htonl(1) != 1);

        uint32_t crc;

        fingerprint.clear();
        fingerprint.reserve(21);

        if (filesize <= CRC_SIZE)
        {
            memset(data + filesize, 0, CRC_SIZE - filesize);
            fingerprint.assign(data, CRC_SIZE);
        }
        else if (filesize <= (off_t)sizeof data)
        {
            int oldp = 0;

            for (int i = 0; i < SLICES; i++)
            {
                int newp = (i + 1) * filesize / SLICES;

                crc = htonl(CRC32::crc32b(data + oldp, newp - oldp));
                fingerprint.append((const char*)&crc, sizeof crc);

                oldp = newp;
            }
        }
        else
        {
            for (int i = 0; i < SLICES; i++)
            {
                crc = htonl(CRC32::crc32b(data + i * sizeof data / SLICES, sizeof data / SLICES));
                fingerprint.append((const char*)&crc, sizeof crc);
            }
        }

        for (int i = sizeof mtime; i--; )
        {
            if (((char*)&mtime)[i])
            {
                fingerprint.append(1, (char)(i + 1));
                fingerprint.append((const char*)&mtime, i + 1);
                break;
            }
        }
    }
};

// FIXME: placeholder - integrate with the actual SDK functionality
struct ChunkedEncryptMAC
{
    std::map<off_t, mac_t> mChunkMacs;

    static const int BLOCKSIZE = 16;

    // FIXME: integrate with SDK
    mac_t encryptAndComputeMac(off_t pos, char* data, int len)
    {
        return 0;
    }

    void apply(off_t pos, mac_t mac)
    {
        mChunkMacs[pos] = mac;
    }

    bool finish()
    {
        off_t pos {0};

        for (auto it = mChunkMacs.begin(); it != mChunkMacs.end(); it++)
        {
            if (pos != it->first)
            {
                // FIXME: fail upload
                std::cout << "Missing chunk at pos == " << pos << std::endl;
                return false;
            }

            pos += g_chunkMap.chunksize(pos);
        }

        return true;
    }
};

// this holds the changes to apply to the chunked MAC and the file fingerprint
// upon the server confirming the chunk
struct ChunkFingerprintMacUpdate
{
    std::vector<std::pair<short, std::string>> mFingerprintPieces;
    mac_t mMac;

    ChunkFingerprintMacUpdate(ChunkedEncryptMAC& cem, off_t pos, char* data, int len, off_t filesize);

    void apply(off_t pos, ChunkedEncryptMAC& cem, FileFingerprint& fingerprint)
    {
        fingerprint.apply(mFingerprintPieces);
        cem.apply(pos, mMac);
    }
};

typedef uint32_t dstime_t;

struct SteadyTime
{
    // monotonically increasing (but wrapping) deciseconds - subtract first, compare later!
    static dstime_t ds()
    {
        dstime_t ds = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count() / 100;

        // we never return 0 (which sometimes serves as a flag)
        return ds ? ds : 1;
    }

    // sleep for specified number of deciseconds
    static void sleep_ds(dstime_t ds)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(ds * 100));
    }

    // returns t1 - t2 as a *signed* int
    inline static int32_t difference(dstime_t t1, dstime_t t2)
    {
        return (int32_t)(t1 - t2);
    }
};

struct WsUploadFile
{
    // interval between upload retries, in ds
    static const int32_t RETRYINTERVAL = 60 * 10;

    // unique at all times
    uint32_t mFileNo;

    // true once we are in the WsTransferQueue
    bool mInQueue {false};

    // the WsTransferQueue::filelist iterator
    file_list::iterator mFiles_it;

    // the WsPool the file is being uploaded by (or nullptr)
    struct WsPool* mPool {nullptr};

    // POSIX file descriptor and properties
    // FIXME: use SDK's fs abstraction layer instead
    int fd;
    time_t mtime;
    off_t size;

    // FIXME: replace with SDK-relevant data structure
    std::string mCredentials;

    // the current read position while sending
    off_t mHeadPos {0};

    // throughput metering/server state loss detection
    off_t mBytesConfirmed {0};
    off_t mLastReportedBytesConfirmed;

    dstime_t mUploadStartTime {0}, mUploadCompletionTime {0}, mUploadFailedTime;

    // true: the EOF chunk has been sent
    bool mEofSet {false};

    bool mAborted {false};
    bool mPaused {false};

    ChunkedEncryptMAC mChunkedEncryptMAC;
    FileFingerprint mFingerprint;

    void printHex(const char* ptr, int len)
    {
        while (len--) printf("%02x", (unsigned char)*ptr++);
    }

    void unsetPool();
    void setPool(WsPool* newpool);

    bool continuingUpload();

    void cancel()
    {
        mAborted = true;
    }

    void uploadFailed(const char reason)
    {
        mUploadFailedTime = SteadyTime::ds();
        unsetPool();

        std::cout << "WsUpload: File " << mCredentials << " failed to upload: " << static_cast<int>(reason) << std::endl;
    }

    void uploadComplete(const char* response, int len)
    {
        mUploadCompletionTime = SteadyTime::ds();
        unsetPool();

        // FIXME: is this correct?
        if (len == 36)
        {
            if (mChunkedEncryptMAC.finish())
            {
                // FIXME: integrate with the SDK framework
                std::cout << "WsUpload: File " << mCredentials << " uploaded successfully in " << SteadyTime::difference(mUploadCompletionTime, mUploadStartTime)/10 << " seconds: ";
                printHex(response, len);
                std::cout << std::endl;


                // extract fingerprint
                std::string file_fingerprint;
                mFingerprint.get(size, mtime, file_fingerprint);
                std::cout << "Fingerprint: ";
                printHex(file_fingerprint.data(), file_fingerprint.size());
                std::cout << std::endl;
            }
            else
            {
                std::cout << "WsUpload: File " << mCredentials << " - internal error at MAC completion" << std::endl;
            }
        }
        else
        {
            std::cout << "WsUpload: File " << mCredentials << " invalid upload completion: ";
            printHex(response, len);
            std::cout << std::endl;

            // FIXME: retry
        }
    }

    void showThroughput();

    bool readData(char* buf, off_t pos, int len);

    WsUploadFile(uint32_t fileno, int fd, const char* credentials);
    ~WsUploadFile();
};

// obtains size classes and related upload URLs from the API
// creates a WsPool for each
// refreshes WsPools when needed, closes them when traffic has bled off the old ones
struct WsPoolMgr
{
    // time after which connections are reduced back to 1 following the completion of the last upload, in ds
    static const int32_t POOLCONNKEEPALIVE = 60 * 10;

    // interval before a pool goes stale and needs to be refreshed, in ds
    static const int32_t POOLFRESHNESS = 24 * 3600 * 10;

    // maximum time a server has to respond before considered down
    const int32_t SERVERTIMEOUT = 20 * 10;

    std::vector<std::unique_ptr<WsPool>> mPools;

    // files that have seen progress, for throughput reporting
    std::unordered_set<WsUploadFile*> mActiveFiles;

    // curl layer for `usc` API request - FIXME: use SDK API layer instead
    CURLM* curlm;

     // maps easy_handles to their response processor
    std::unordered_map<CURL*, struct CurlResponseProc*> mCurlProcs;
    void setCurlResponseProc(CURL*, struct CurlResponseProc*);

    // last successful read from the network
    dstime_t mLastNetRead {0};
    void bumpLastNetRead();

    // user-configured number of connections per active pool
    unsigned char mNumberOfConnectionsPerPool {1};
    void setNumConn(unsigned char numConn);

    bool mRefreshingPools {false};
    void refreshPools();
    bool refreshPoolsResponse(std::string&);

    void curlIO();

    void checkPools();
    void bumpAllPools();

    WsPoolMgr()
    {
        curlm = curl_multi_init();
        refreshPools();
    }
};

struct WsTransferQueue
{
    // the ordered upload queue
    file_list mFiles;

    // maps fileno to WsUploadFile*
    std::unordered_map<uint32_t, WsUploadFile*> mFileMap;

    // this is incremented with every change, invalidating existing pool files
    uint32_t mQueueVersion;

    // the next file to upload (or mFiles.begin() if unknown)
    file_list::iterator mNextFile;

    // add/remove/move file to/from/within the transfer queue
    // we bump mQueueVersion to invalidate all WsPool::mUploadingFiles
    void add(WsUploadFile* file, WsUploadFile* before = nullptr)
    {
        mQueueVersion++;

        file->mFiles_it = mFiles.insert((before && before->mInQueue) ? before->mFiles_it : mFiles.end(), file);
        file->mInQueue = true;

        // must start the search from scratch unless we were inserting at the end
        if (!before) mNextFile = mFiles.begin();
    }

    void remove(WsUploadFile* file)
    {
        mQueueVersion++;

        // are we cancelling the next file scheduled to be uploaded?
        if (mNextFile == file->mFiles_it) mNextFile++;

        mFiles.erase(file->mFiles_it);
        file->mInQueue = false;

        if (file->mPool)
        {
            file->cancel();
            file->mPool = nullptr;
        }
    }

    void pause(WsUploadFile* file)
    {
        file->mPaused = true;
    }

    void unPause(WsUploadFile* file)
    {
        file->mPaused = false;
    }

    // locates and returns a suitable file for uploading
    // checks suitable size and (mPool == nullptr && !mUploadCompletionTime)
    WsUploadFile* getNextUpload(off_t minSize, off_t maxSize)
    {
        bool consecutive = true;

        // always start search at mNextFile for predominantly O(1) complexity
        for (auto it = mNextFile; it != mFiles.end(); it++)
        {
            WsUploadFile* uploadFile {*it};

            // is file not currently being uploaded and not completed?
            if (!uploadFile->mPool && !uploadFile->mPaused && uploadFile->continuingUpload())
            {
                // is file size suitable for the pool?
                if (uploadFile->size >= minSize && (!maxSize || uploadFile->size < maxSize))
                {
                    // adjust mNextFile to shorten next search
                    if (consecutive)
                    {
                        it++;
                        mNextFile = it;
                        return uploadFile;
                    }
                }

                consecutive = false;
            }
        }

        return nullptr;
    }

    WsTransferQueue() :
        mNextFile(mFiles.begin())
    {
    }
};

struct WsUploadMgr
{
    WsPoolMgr mPoolMgr;
    WsTransferQueue mTransferQueue;

    std::thread* mUploadThread;

    dstime_t mCurrentTime;

    uint32_t mNextFileNo {0};

    bool mPaused {false};

    void uploadMgrThread();

    // this is the only mutex in this subsystem, and it remains firmly locked by
    // all upload-related threads, including the application thread, except in the
    // following situations:
    // * a thread sleeps
    // * a thread performs a CPU- or time-intensive operation, such as
    //   - disk I/O
    //   - network activity
    //   - chunk encryption/MAC

    std::mutex mUploadMutex;

    void unlockMutex()
    {
        mUploadMutex.unlock();
    }

    void lockMutex()
    {
        mUploadMutex.lock();
    }

    // sleep with uploadmutex unlocked
    void unlockedSleep_ds(uint32_t ds)
    {
        unlockMutex();
        SteadyTime::sleep_ds(ds);
        lockMutex();
    }

    // insert upload into the queue
    // fileno *must* be unique, lower filenos get uploaded first
    void upload(uint32_t fileno, int fd, const char*);

    // set the number of connections per size class
    void setNumConn(unsigned char numConn);

    // instantiate WsUploadFile object
    WsUploadFile* wsUploadFile(int fd, const char* credentials);

    // lock upload mutex and start management thread
    void startUp()
    {
        lockMutex();
        mUploadThread = new std::thread(&WsUploadMgr::uploadMgrThread, this);
    }

    void pauseAll()
    {
        mPaused = true;
    }

    void unpauseAll()
    {
        // we need to bump the last activity timestamp of all pools
        // after a lengthy pause to avoid false timeouts
        mPoolMgr.bumpAllPools();
        mPaused = false;
    }
} g_wsUploadMgr;

#pragma pack(push, 1)
struct WsChunk
{
    off_t pos;
    int len;
    uint32_t fileno;
};
#pragma pack(pop)

// linear fixed-sized buffer that can send itself to a WebSocket curl connection
struct WsBuf
{
    // header + max chunk size
    char buf[20 + MB];

    int mSendPos;
    int mDataLen;

    void add(const char* data, int len)
    {
        memcpy(buf + mDataLen, data, len);
        mDataLen += len;
    }

    void reset()
    {
        mDataLen = 0;
        mSendPos = 0;
    }

    bool sendWS(struct WsConn* ws, int& bufferedAmount);

    WsBuf()
    {
        reset();
    }
};

// generic curl response processor (used only by the WsPoolMgr to process the API response)
struct CurlResponseProc
{
    CURL* curl;
    std::string response;

    void append(const char* data, int len)
    {
        response.append(data, len);
    }

    virtual void curlIO() {}
    virtual bool done(bool success) = 0;

    ~CurlResponseProc()
    {
        if (curl) g_wsUploadMgr.mPoolMgr.mCurlProcs.erase(curl);
    }
};

struct CurlResponseProcRefreshPools : CurlResponseProc
{
    WsPoolMgr* mPoolMgr;

    CurlResponseProcRefreshPools(WsPoolMgr* poolmgr) :
        mPoolMgr(poolmgr)
    {
    }

    bool done(bool success)
    {
        if (!success || !mPoolMgr->refreshPoolsResponse(response))
        {
            // FIXME: retry
        }

        return true;
    }
};

#pragma pack(push,1)
struct ChunkHeader
{
    uint32_t fileno;
    off_t pos;
    int len;
    uint32_t crc;
};
#pragma pack(pop)

// curl WebSocket connection handling
struct WsConn
{
    CURL* curl;
    int bufferedAmount {0};

    enum ReadyState : char { CONNECTING, OPEN, CLOSING, CLOSED } readyState {CLOSED};

    // double-buffered reading/sending - mCurBuf alternates between mBufs[0] and [1]
    WsBuf mBufs[2];
    char mCurBuf {0};

    // if set, the connection is about to close
    bool mClosing {false};

    // server response
    char mInBufPos {0};
    char mInBuf[64];

    // backpointer to pool the connection belongs to
    struct WsPool* mPool;

    std::unordered_set<WsConn*>::iterator mConns_it;

    // chronological record of the unacknowledged chunks in transit (for requeueing if connection drops)
    // and the in-flight chunks' contribution to fingerprint/MAC (for application if server confirms)
    std::vector<std::pair<WsChunk, ChunkFingerprintMacUpdate>> mChunksInFlight;

    bool connectWS();
    void closeWS();

    void onopen();
    void onclose();

    void curlSend();
    void curlRecv();

    bool haveSpace();
    bool readyForData();
    void onmessage(const char* msg, int len);

    void senddata(int buf, const char* data, int len)
    {
        mBufs[buf].add(data, len);
        bufferedAmount += len;
    }

    void sendChunkData(uint32_t fileno, off_t pos, const char* data, int len);

    WsConn(WsPool* pool);
    ~WsConn();
};

// thread pool element
struct WsPoolThread
{
    std::thread t;
    bool terminate {false};
    bool terminated {false};

    WsPoolThread(WsPool* pool);
    ~WsPoolThread()
    {
        t.join();
    }
};

// there is one WsPool per file size class URL
// it holds files to upload, threads (connections) to the URL
struct WsPool
{
    // interval between connection attempts, in ds
    static const int32_t CONNRETRYINTERVAL = 5 * 10;

    // minimum time of inactivity, plus four times the time elapsed, before an upload is abandoned
    static const int32_t UPLOADTIMEOUT = 180 * 10;

    // connections in this pool
    std::unordered_set<WsConn*> mConns;

    // chunks to be resent
    std::vector<WsChunk> mToResend;

    // thread pools
    std::vector<std::unique_ptr<WsPoolThread>> mActiveThreads, mExitingThreads;

    // the number of WsUploadFiles that have their mPool pointing at us
    int mNumPoolFiles {0};

    // the file currently being sent by this pool
    WsUploadFile* mUploadingFile {nullptr};

    // the WsTransferQueue version prevailing at the time mUploadingFile was picked
    uint32_t mUFTQversion {0};

    // pool creation time
    dstime_t mPoolCreationTime;

    std::string mUrl;        // upload wss:// URL

    // file size range this pool uploads
    off_t mMinFileSize, mMaxFileSize;

    // number of chunks in flight
    int mNumChunksInFlight {0};

    // last time this pool saw activity
    dstime_t mLastActive {g_wsUploadMgr.mCurrentTime};

    // last time this pool heard from its server
    dstime_t mLastServerResponse {g_wsUploadMgr.mCurrentTime};

    // if non-0, stop sending chunks until SteadyTime::ds() surpasses it (server-initiated throttling)
    dstime_t mPausedByServerUntil {0};

    // user-configured number of open connections while uploading
    unsigned char mNumberOfConnections {1};

    // a retiring pool no longer receives new uploads and closes after completion of the last one
    bool mRetiring {false};

    void poolWorkerThread(struct WsPoolThread* poolthread);

    void checkThreads();

    // change the actual number of connections in this pool
    void setPoolNumConn(unsigned char newnumconn)
    {
        mNumberOfConnections = newnumconn;
        checkThreads();
    }

    // true if pool has residual activity: cannot be closed yet
    bool stillActive()
    {
        // still uploading/finishing at least one file
        if (mNumPoolFiles)
        {
            // below minimum grace period after last confirmed network activity?
            // grant additional grace period for long-running uploads (four times the absolute time spent uploading)
            if (SteadyTime::difference(g_wsUploadMgr.mCurrentTime, g_wsUploadMgr.mPoolMgr.mLastNetRead) < UPLOADTIMEOUT + (mUploadingFile ? 4 * SteadyTime::difference(g_wsUploadMgr.mCurrentTime, mUploadingFile->mUploadStartTime) : 0)) return true;
        }

        if (!mNumberOfConnections)
        {
            checkThreads();

            // must wait for threads to terminate
            return !mActiveThreads.empty() || !mExitingThreads.empty();
        }

        // request termination of all threads and remain active in the meantime
        setPoolNumConn(0);
        return true;
    }

    // (this assumes that the URLs start with a three-character URI scheme, followed by three characters (://)
    bool freshAndSameHostMaxSize(std::pair<std::string, off_t>& urlMaxSize, dstime_t oldestvalid)
    {
        // expired?
        if (SteadyTime::difference(mPoolCreationTime, oldestvalid) < 0) return false;

        // maxsize identical?
        if (mMaxFileSize != urlMaxSize.second) return false;

        // URL pointing to same hostname?
        for (int i = 6; i < static_cast<int>(urlMaxSize.first.size()) && i < static_cast<int>(mUrl.size()); i++)
        {
            if (mUrl[i] != urlMaxSize.first[i]) return false;
            if (mUrl[i] == '/') return true;
        }

        return false;
    }

    // request pause in sending data for ms milliseconds
    void pauseSending(dstime_t ds)
    {
        mPausedByServerUntil = SteadyTime::ds() + ds;
    }

    // check if server throttling is active
    bool throttledByServer()
    {
        if (!mPausedByServerUntil) return false;

        if (SteadyTime::difference(SteadyTime::ds(), mPausedByServerUntil) > 0)
        {
            mPausedByServerUntil = 0;
            return false;
        }

        return true;
    }

    // set current or next file to upload
    // also sets the prevailing transfer queue version at the time the file started
    bool getUploadFile()
    {
        // we have an active file, and the transfer queue hasn't changed: continue upload
        if (mUploadingFile && !mUploadingFile->mPaused && mUploadingFile->continuingUpload() && mUFTQversion == g_wsUploadMgr.mTransferQueue.mQueueVersion) return true;

        // (inactive pools cannot start new files)
        if (mRetiring) return false;

        mUploadingFile = g_wsUploadMgr.mTransferQueue.getNextUpload(mMinFileSize, mMaxFileSize);

        if (mUploadingFile)
        {
            mUploadingFile->mUploadStartTime = SteadyTime::ds();

            // mark version and assign to this pool
            mUFTQversion = g_wsUploadMgr.mTransferQueue.mQueueVersion;
            mUploadingFile->setPool(this);

           return true;
        }

        return false;
    }

    // return the WsUploadFile* for fileno if the file's pool ptr points to us, nullptr otherwise
    WsUploadFile* findFile(uint32_t fileno)
    {
        // shortcut to save CPU cycles: check active file (which is mostly the one we're looking for)
        if (mUploadingFile && mUploadingFile->mFileNo == fileno)
        {
            if (mUploadingFile->mPool == this) return mUploadingFile;
            return nullptr;
        }

        // otherwise, we have to consult the global unordered_map
        auto it = g_wsUploadMgr.mTransferQueue.mFileMap.find(fileno);
        if (it == g_wsUploadMgr.mTransferQueue.mFileMap.end() || it->second->mPool != this) return nullptr;
        return it->second;
    }

    // returns [position, size, fileno] of next chunk, or false if we're done
    bool nextChunk(WsChunk& chunk)
    {
        // do we have any failed chunks that need to be resent? do these first
        while (!mToResend.empty())
        {
            chunk = mToResend[0];
            mToResend.erase(mToResend.begin());

            std::cout << "WsUpload: Resending chunk " << chunk.pos << " " << chunk.len << " for " << chunk.fileno << std::endl;

            // return chunk unless the file upload has ben cancelled
            if (findFile(chunk.fileno)) return true;
        }

        // globally paused
        if (g_wsUploadMgr.mPaused) return false;

        // send chunks from current file (move along the transfer queue if needed)
        // for files ending on a chunk boundary, an extra empty chunk needs to be sent
        // to set its final size
        while (getUploadFile())
        {
            if (mUploadingFile->mHeadPos < mUploadingFile->size || !mUploadingFile->mEofSet)
            {
                chunk.fileno = mUploadingFile->mFileNo;

                if (mUploadingFile->mHeadPos == mUploadingFile->size)
                {
                    // generate empty chunk
                    mUploadingFile->mEofSet = true;
                    chunk.len = 0;
                }
                else
                {
                    chunk.pos = mUploadingFile->mHeadPos;

                    // advance headpos by one chunk
                    mUploadingFile->mHeadPos += g_chunkMap.chunksize(mUploadingFile->mHeadPos);

                    if (mUploadingFile->mHeadPos > mUploadingFile->size)
                    {
                        // not on a chunk boundary: size is set by this chunk
                        mUploadingFile->mHeadPos = mUploadingFile->size;
                        mUploadingFile->mEofSet = true;
                    }

                    chunk.len = mUploadingFile->mHeadPos - chunk.pos;
                }

                mLastActive = g_wsUploadMgr.mCurrentTime;
                return true;
            }

            mUploadingFile = nullptr;  // we're done with this file
        }

        return false;
    }

    // retry single chunk
    void retryChunk(WsChunk& chunk)
    {
        std::cout << "WsUpload: Going to retry chunk " << chunk.pos << " " << chunk.len << " " << chunk.fileno << std::endl;

        mToResend.push_back(chunk);
    }

    // retry all chunks in flight
    void retryChunksOnTheWire(WsConn* ws)
    {
        // the connection dropped unexpectedly: we return the in-flight chunk to the pool
        std::cout << "WsUpload: WebSocket connection to " << mUrl << " lost" << std::endl;

        // we must resend all unacknowledged in-flight chunks
        for (int i = 0; i < static_cast<int>(ws->mChunksInFlight.size()); i++)
        {
            std::cout << "WsUpload: Retrying chunk " << ws->mChunksInFlight[i].first.pos << " " << ws->mChunksInFlight[i].first.len << " "  << ws->mChunksInFlight[i].first.fileno << std::endl;

            retryChunk(ws->mChunksInFlight[i].first);
        }

        mNumChunksInFlight -= ws->mChunksInFlight.size();
        ws->mChunksInFlight.clear();
    }

    // apply and remove all in-flight chunks for a fileno
    void applyInFlight(uint32_t fileno, ChunkedEncryptMAC* cem = nullptr, FileFingerprint* fingerprint = nullptr)
    {
        for (auto& conn : mConns)
        {
            for (int j = conn->mChunksInFlight.size(); j--; )
            {
                if (conn->mChunksInFlight[j].first.fileno == fileno)
                {
                    if (cem) conn->mChunksInFlight[j].second.apply(conn->mChunksInFlight[j].first.pos, *cem, *fingerprint);
                    conn->mChunksInFlight.erase(conn->mChunksInFlight.begin() + j);
                    mNumChunksInFlight--;
                }
            }
        }
    }

    // send one chunk from the WsPool to the given WebSocket
    // returns true if something was sent, false otherwise
    bool sendChunk(WsConn* ws)
    {
        // if connection is up and buffer is not too full, we send another chunk
        if (ws->readyState == WsConn::OPEN && ws->haveSpace())
        {
            WsChunk chunk;

            // chunk is [chunkpos, len, fileno]
            if (nextChunk(chunk))
            {
                // ensure that we always have the desired number of threads running
                if (ws->mPool->mNumberOfConnections != g_wsUploadMgr.mPoolMgr.mNumberOfConnectionsPerPool)
                {
                    ws->mPool->mNumberOfConnections = g_wsUploadMgr.mPoolMgr.mNumberOfConnectionsPerPool;
                    ws->mPool->checkThreads();
                }

                char buf[MB];

                WsUploadFile* uf = findFile(chunk.fileno);

                if (uf && !uf->mAborted && uf->readData(buf, chunk.pos, chunk.len))
                {
                    // this will encrypt buf
                    ws->mChunksInFlight.push_back({ chunk, ChunkFingerprintMacUpdate(uf->mChunkedEncryptMAC, chunk.pos, buf, chunk.len, uf->size) });
                    ws->sendChunkData(chunk.fileno, chunk.pos, buf, chunk.len);

                    // mark the sent chunk as in flight on this connection/file
                    mNumChunksInFlight++;
                    return true;
                }
            }
        }

        return false;
    }

    // the actual upload work:
    // * read from file * encrypt/MAC * send to WebSocket
    // * receive and action server responses * manage connection
    WsPool(std::pair<std::string, off_t> urlmaxsize, off_t minsize) :
        mPoolCreationTime(SteadyTime::ds()),
        mUrl(urlmaxsize.first),
        mMinFileSize(minsize),
        mMaxFileSize(urlmaxsize.second)
    {
        checkThreads();
    }
};

// reading file data...
bool WsUploadFile::readData(char* buf, off_t pos, int len)
{
    g_wsUploadMgr.unlockMutex();

    // FIXME: use SDK's fs abstraction layer
    if (pread(fd, buf, len, pos) != len)
    {
        perror("pread() failed");
        mUploadFailedTime = SteadyTime::ds();

        g_wsUploadMgr.lockMutex();
        return false;
    }

    g_wsUploadMgr.lockMutex();

    return true;
}
// ...and encryption/MAC computation happen with the upload mutex unlocked
ChunkFingerprintMacUpdate::ChunkFingerprintMacUpdate(ChunkedEncryptMAC& cem, off_t pos, char* data, int len, off_t filesize)
{
    g_wsUploadMgr.unlockMutex();

    FileFingerprint::extractSparseData(pos, data, len, filesize, mFingerprintPieces);
    mMac = cem.encryptAndComputeMac(pos, data, len);

    g_wsUploadMgr.lockMutex();
}

// returns true if the file should still be uploaded, false otherwise
// does not take into consideration paused state!
bool WsUploadFile::continuingUpload()
{
    // standard case
    if (!mAborted && !mUploadCompletionTime) return true;

    if (mUploadFailedTime && SteadyTime::difference(g_wsUploadMgr.mCurrentTime, mUploadFailedTime) > RETRYINTERVAL) return true;

    return false;
}

WsUploadFile::WsUploadFile(uint32_t fileno, int fd, const char* credentials) :
    mFileNo(fileno),
    fd(fd),
    mCredentials(credentials)
{
    // FIXME: replace with the SDK's fs abstraction layer
    struct stat statbuf;

    if (fstat(fd, &statbuf) < 0)
    {
        // something went terribly wrong, don't upload this file
        size = 0;
        mUploadFailedTime = SteadyTime::ds();
    }
    else
    {
        size = statbuf.st_size;
        mtime = statbuf.st_mtime;
        mUploadFailedTime = 0;
    }

    g_wsUploadMgr.mTransferQueue.mFileMap[fileno] = this;
}


static size_t writefunc(void *ptr, size_t, size_t nmemb, CurlResponseProc *proc)
{
    proc->append((const char*)ptr, nmemb);
    return nmemb;
}


WsPoolThread::WsPoolThread(WsPool* pool) :
    t(std::thread(&WsPool::poolWorkerThread, pool, this))
{
}

void WsConn::sendChunkData(uint32_t fileno, off_t pos, const char* data, int len)
{
    g_wsUploadMgr.unlockMutex();

    // header: fileno (32 bit LE) + pos (64 bit LE) + length (32 bit LE) + CRC32b (32 bit LE) over the first 16 bytes of the header + the chunk data
    struct ChunkHeader header;

    header.fileno = fileno;
    header.pos = pos;
    header.len = len;
    header.crc = CRC32::crc32b(data, len, CRC32::crc32b((char*)&header, offsetof(struct ChunkHeader, crc)));

    // double buffering: we send to mCurBuf if empty, otherwise to !mCurBuf
    char buf {mCurBuf};
    if (mBufs[static_cast<short>(buf)].mDataLen) buf = !buf;

    senddata(buf, (char*)&header, sizeof header);
    senddata(buf, data, len);

    g_wsUploadMgr.lockMutex();
}

void WsPool::poolWorkerThread(WsPoolThread* poolThread)
{
    int retryCount {0};
    uint32_t lastQueueVersion = g_wsUploadMgr.mTransferQueue.mQueueVersion;

    WsConn ws(this);

    g_wsUploadMgr.lockMutex();

    while (!poolThread->terminate)
    {
        if (ws.readyState == WsConn::CLOSED)
        {
            if (!ws.connectWS())
            {
                if (!retryCount++) continue;

                // when we can't connect to the server, but the transfer queue has changed,
                // we refresh the pools (just in case the existing target server has died)
                if (!mRetiring && lastQueueVersion != g_wsUploadMgr.mTransferQueue.mQueueVersion)
                {
                    g_wsUploadMgr.mPoolMgr.refreshPools();
                }

                g_wsUploadMgr.unlockedSleep_ds(CONNRETRYINTERVAL);
                continue;
            }

            retryCount = 0;
        }

        // record transfer queue version when connection was still up
        lastQueueVersion = g_wsUploadMgr.mTransferQueue.mQueueVersion;

        // process server responses
        ws.curlRecv();

        // are we in a server-requested paused state (send throttling)?
        if (throttledByServer())
        {
            g_wsUploadMgr.unlockedSleep_ds(1);
            continue;
        }

        // send enqueued chunk data
        ws.curlSend();

        // do not overfill send buffers
        if (!ws.haveSpace())
        {
            g_wsUploadMgr.unlockedSleep_ds(2);
            continue;
        }

        if (!ws.readyForData())
        {
            g_wsUploadMgr.unlockedSleep_ds(2);
            continue;
        }

        // fetch & enqueue a file chunk
        if (!sendChunk(&ws))
        {
            g_wsUploadMgr.unlockedSleep_ds(10);
            continue;
        }
    }

    poolThread->terminated = true;
    g_wsUploadMgr.unlockMutex();
}

// create/terminate threads as directed
void WsPool::checkThreads()
{
printf("checkThreads(), numconn=%d\n", mNumberOfConnections);
    while (mActiveThreads.size() < mNumberOfConnections)
    {
        mActiveThreads.push_back(std::make_unique<WsPoolThread>(this));
    }

    while (mActiveThreads.size() > mNumberOfConnections)
    {
        std::unique_ptr<WsPoolThread> poolthread {std::move(mActiveThreads.back())};
        mActiveThreads.pop_back();

        poolthread->terminate = true;
        mExitingThreads.push_back(std::move(poolthread));
    }

    for (int i = mExitingThreads.size(); i--; )
    {
        if (mExitingThreads[i]->terminated)
        {
            mExitingThreads.erase(mExitingThreads.begin() + i);
        }
    }
}

// must be called without changes to buf until it returns true
bool WsBuf::sendWS(WsConn* ws, int& bufferedAmount)
{
    if (mSendPos < mDataLen)
    {
        size_t sent;

        g_wsUploadMgr.unlockMutex();
        CURLcode res = curl_ws_send(ws->curl, buf + mSendPos, mDataLen - mSendPos, &sent, 0, CURLWS_BINARY);
        g_wsUploadMgr.lockMutex();

        if (res == CURLE_OK)
        {
            mSendPos += sent;
            bufferedAmount -= sent;

            if (mSendPos == mDataLen)
            {
                // no data left in buffer to send, empty it and signal a switch
                reset();
                return true;
            }
        }
        else
        {
            if (res != 81)
            {
                std::cout << "CURL ERROR: curl_ws_send() returns " << res << std::endl;
                ws->readyState = WsConn::CLOSED;
                ws->onclose();
            }
        }
    }

    return false;
}

// disassociate file from its pool
void WsUploadFile::unsetPool()
{
    if (mPool)
    {
        mPool->mNumPoolFiles--;
        mPool = nullptr;
    }
}

// associate file with this pool
void WsUploadFile::setPool(WsPool* pool)
{
    unsetPool();

    mPool = pool;
    mPool->mNumPoolFiles++;
}

WsUploadFile::~WsUploadFile()
{
    close(fd);

    g_wsUploadMgr.mTransferQueue.mFileMap.erase(mFileNo);
    g_wsUploadMgr.mPoolMgr.mActiveFiles.erase(this);

    if (mPool)
    {
        mPool->applyInFlight(mFileNo);
        mPool->mUploadingFile = nullptr;
        unsetPool();
    }
}

// attach response processor to a curl easy_handle
void WsPoolMgr::setCurlResponseProc(CURL* curl, struct CurlResponseProc* proc)
{
    proc->curl = curl;
    mCurlProcs[curl] = proc;

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, proc);
    curl_multi_add_handle(curlm, curl);
}

// set desired number of connections
void WsPoolMgr::setNumConn(unsigned char numConn)
{
    // we keep one connection per pool open and ramp it up when a file is queued
    mNumberOfConnectionsPerPool = numConn;

    // if files are being transferred, the change takes effect immediately
    for (int i = mPools.size(); i--; )
    {
        if (mPools[i]->mUploadingFile) mPools[i]->setPoolNumConn(numConn);
    }
}

void WsPoolMgr::bumpLastNetRead()
{
    if (SteadyTime::difference(g_wsUploadMgr.mCurrentTime, mLastNetRead) > 0) mLastNetRead = g_wsUploadMgr.mCurrentTime;
}

void WsPoolMgr::curlIO()
{
    int still_running, msgs_left;

    curl_multi_perform(curlm, &still_running);

    CURLMsg* msg;

    for (auto it = mCurlProcs.begin(); it != mCurlProcs.end(); it++)
    {
        if (it->second) it->second->curlIO();
    }

    while ((msg = curl_multi_info_read(curlm, &msgs_left)))
    {
        if (msg->msg == CURLMSG_DONE)
        {
            CURL* curl = msg->easy_handle;

            CurlResponseProc* proc = mCurlProcs[curl];

            if (proc && proc->done(msg->data.result == CURLE_OK))
            {
                curl_multi_remove_handle(curlm, curl);
                mCurlProcs.erase(curl);
            }
        }
    }

    g_wsUploadMgr.mUploadMutex.unlock();
    CURLMcode mc = curl_multi_poll(curlm, nullptr, 0, 500, NULL);
    g_wsUploadMgr.mUploadMutex.lock();

    if (mc != CURLM_OK)
    {
        std::cerr << "curl_multi_poll failed" << std::endl;
        exit(0);
    }
}

// closes dead pools
// reduces threadcount to 1 after an upload
// refreshes pools if a server is stuck
// invokes filethroughput()
void WsPoolMgr::checkPools()
{
    int i;

    // bump mLastNetRead
    for (i = mPools.size(); i--; )
    {
        if (SteadyTime::difference(mPools[i]->mLastServerResponse, mLastNetRead) > 0) mLastNetRead = mPools[i]->mLastServerResponse;
    }

    // delete empty extra pools (the non-active ones follow the active ones in pools)
    for (i = mPools.size(); i-- && mPools[i]->mRetiring; )
    {
        if (!mPools[i]->stillActive())
        {
            std::cout << "WsUpload: Closing idle pool " << i << " (" << mPools[i]->mUrl << ")";
            mPools.erase(mPools.begin() + i);
        }
    }

    // reduce connection count in pools that haven't seen activity
    while (i >= 0)
    {
        if (mPools[i]->mNumberOfConnections > 1 && SteadyTime::difference(g_wsUploadMgr.mCurrentTime, mPools[i]->mLastActive) > POOLCONNKEEPALIVE)
        {
            mPools[i]->mNumberOfConnections = 1;
            mPools[i]->checkThreads();
        }

        // if any active pool has gone stale, go back to the API for a refresh
        if (!mRefreshingPools && SteadyTime::difference(g_wsUploadMgr.mCurrentTime, mPools[i]->mPoolCreationTime) > POOLFRESHNESS)
        {
            refreshPools();
        }

        // refresh pools if any non-retiring pool has been unsuccessful in communicating with its URL for at least SERVERTIMEOUT ms
        if ((mPools[i]->mUploadingFile || mPools[i]->mNumChunksInFlight || mPools[i]->mToResend.size())
            && SteadyTime::difference(g_wsUploadMgr.mCurrentTime, mPools[i]->mLastActive) > SERVERTIMEOUT)
        {
            refreshPools();
        }

        i--;
    }

    // show throughput for active files
    for (auto fu : mActiveFiles) fu->showThroughput();
    mActiveFiles.clear();
}

// create new WsPools for each size class based on the API response
bool WsPoolMgr::refreshPoolsResponse(std::string& response)
{
    std::vector<std::pair<std::string, off_t>> apiSizeClasses;

    std::string url;

    bool success {false};

    const char* ptr {response.c_str()};
    const char* ptr2;

    std::cout << "API response: " << ptr << std::endl;

    // FIXME: might segfault on SIMD systems with poorly designed memcmp() routines
    if (!memcmp(ptr, "[[[\"", 3))
    {
        for (;;)
        {
            ptr += 4;

            if ((ptr2 = strchr(ptr, '"')))
            {
                // FIXME: shall we still do optional plain TCP with port switching?
                url = "wss://";
                url.append(ptr, ptr2 - ptr);
                url.append("/");

                ptr = ptr2 + 3;

                if ((ptr2 = strchr(ptr, '"')))
                {
                    url.append(ptr, ptr2-ptr);
                }

                if (ptr2[1] == ',')
                {
                    apiSizeClasses.push_back({ url, atoll(ptr2+2) });

                    if ((ptr = strchr(ptr2, ']')))
                    {
                        // FIXME: see above
                        if (!memcmp(ptr, "],[\"", 4))
                        {
                            continue;
                        }
                    }
                }
                else
                {
                    apiSizeClasses.push_back({ url, 0 });

                    success = true;
                    break;
                }
            }

            std::cout << "Invalid API response: " << response << std::endl;
        }

        if (success)
        {
            // to survive, a pool must be "fresh", i.e. younger than 24h
            dstime_t oldestvalid {SteadyTime::ds() - POOLFRESHNESS};

            // set existing pools to inactive
            for (int i = 0; i < static_cast<int>(mPools.size()) && !mPools[i]->mRetiring; i++) mPools[i]->mRetiring = true;

            // store API size class allocation and corresponding upload URLs
            for (int i = 0; i < static_cast<int>(apiSizeClasses.size()); i++)
            {
                int j;

                // search for matching fresh WsPool and reactivate
                for (j = mPools.size(); j--; )
                {
                    if (mPools[j]->freshAndSameHostMaxSize(apiSizeClasses[i], oldestvalid))
                    {
                        // non-expired match found: maintain existing pool
                        if (j != i)
                        {
                            // and position at the front of mPools
                            std::swap(mPools[i], mPools[j]);
                        }

                        mPools[i]->mRetiring = false;

                        break;
                    }
                }

                // search for matching pool concluded with no match: we create a fresh one
                if (j < 0)
                {
                    // not found: we create a fresh one, retiring its predecessor, which will be closed after the pool dries up
                    mPools.insert(mPools.begin() + i, std::make_unique<WsPool>(apiSizeClasses[i], i ? apiSizeClasses[i - 1].second : 0));
                }
            }

            bumpLastNetRead();
        }
    }

    mRefreshingPools = false;

    return success;
}

void WsPoolMgr::refreshPools()
{
    CURL* curl;

    // only one refresh at a time
    if (mRefreshingPools) return;
    mRefreshingPools = true;

    // FIXME: use the SDK's API infrastructure instead!
    if ((curl = curl_easy_init()))
    {
        // (the usc command is available without a session only on staging)
        curl_easy_setopt(curl, CURLOPT_URL, "https://staging.api.mega.co.nz/cs");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "[{\"a\":\"usc\"}]");

        // the PoolMgr parses the response to the usc (upload size classes and URLs) API command
        setCurlResponseProc(curl, new CurlResponseProcRefreshPools(this));
    }
}

// set last activity timestamp of all pools to the current time
void WsPoolMgr::bumpAllPools()
{
    for (int i = mPools.size(); i--; )
    {
        mPools[i]->mLastActive = g_wsUploadMgr.mCurrentTime;
        mPools[i]->mLastServerResponse = g_wsUploadMgr.mCurrentTime;
    }
}

// run the datapump if a connection is established/closed
void WsConn::onopen()
{
    std::cout << "WsUpload: Connected to " << mPool->mUrl << std::endl;
}

void WsConn::onclose()
{
    std::cout << "WsUpload: Disconnected from " << mPool->mUrl << std::endl;

    if (mPool)
    {
        // ensure that potentially unsent chunks get retried
        mPool->retryChunksOnTheWire(this);
    }
}

void WsConn::curlSend()
{
    if (readyState != OPEN) return;

    while (mBufs[static_cast<short>(mCurBuf)].sendWS(this, bufferedAmount))
    {
        // switch to empty buffer
        mCurBuf = !mCurBuf;
    }
}

void WsConn::curlRecv()
{
    CURLcode res;

    // FIXME: this needs to be const with newer gccs!
    /*const*/ struct curl_ws_frame *meta = NULL;
    size_t recv;

    // receive and action all pending frames from the server
    for (;;)
    {
        auto ptr = const_cast<const curl_ws_frame**>(&meta);
        res = curl_ws_recv(curl, (void*)(mInBuf + mInBufPos), sizeof mInBuf - mInBufPos, &recv, ptr);

        if (res == CURLE_OK && !meta->bytesleft)
        {
            onmessage(mInBuf, recv);
        }
        else
        {
            if (res != 81 || meta)
            {
                readyState = CLOSED;
                onclose();
                printf("curl_ws_recv() loop ends with res=%d recv=%lu bytesleft=%d\n", res, recv, meta ? (int)meta->bytesleft : -1);
            }

            break;
        }
    }
}

// establish WebSocket connection to pool URL
bool WsConn::connectWS()
{
    if (curl) curl_easy_cleanup(curl);

    curl = curl_easy_init();

    if (!curl)
    {
        readyState = CLOSED;
        return false;
    }

    readyState = CONNECTING;
    curl_easy_setopt(curl, CURLOPT_URL, mPool->mUrl.c_str());
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2);

    g_wsUploadMgr.unlockMutex();

    std::cout << "Connecting to " << mPool->mUrl << std::endl;
    CURLcode res {curl_easy_perform(curl)};

    g_wsUploadMgr.lockMutex();

    if (res == CURLE_OK)
    {
        std::cout << mPool->mUrl << " connected" << std::endl;

        mPool->mLastServerResponse = g_wsUploadMgr.mCurrentTime;

        readyState = OPEN;
        mBufs[0].reset();
        mBufs[1].reset();
        bufferedAmount = 0;
        onopen();

        return true;
    }

    std::cout << mPool->mUrl << " failed to connect (" << res << ")" << std::endl;

    readyState = CLOSED;
    return false;
}

void WsConn::closeWS()
{
    readyState = CLOSING;
    mClosing = true;
}

// returns true if at least one of the buffers is empty (i.e. a chunk can be written)
bool WsConn::haveSpace()
{
    return !bufferedAmount || !mBufs[0].mDataLen || !mBufs[1].mDataLen;
}

// a connection can only accept more data if it isn't closing and it isn't throttled
bool WsConn::readyForData()
{
    return !mClosing;
}

// process server message
void WsConn::onmessage(const char* msg, int len)
{
    mPool->mLastActive = g_wsUploadMgr.mCurrentTime;
    mPool->mLastServerResponse = g_wsUploadMgr.mCurrentTime;
    g_wsUploadMgr.mPoolMgr.bumpLastNetRead();

    // parse and action the message from the upload server
    if (len < 9)
    {
        std::cout << "WsUpload: Invalid server message length " << len << std::endl;
        closeWS();
    }
    else if (*(uint32_t*)(msg + len - sizeof(uint32_t)) != CRC32::crc32b(msg, len - sizeof(uint32_t)))
    {
        // inbound CRC failure is treated as fatal for the connection
        std::cout << "WsUpload: CRC failed, byteLength=" << len << std::endl;
        closeWS();
    }
    else
    {
#pragma pack(push,1)
        struct ChunkResponse
        {
            uint32_t fileno;
            off_t chunkpos;
            char event;
        };
#pragma pack(pop)

        // (the amount of line noise required to replace this with a static_cast is unacceptable)
        const ChunkResponse* response {(const ChunkResponse*)msg};
        WsChunk chunk;

        // ignore messages about files that have been cancelled
        WsUploadFile* responseUploadFile {mPool->findFile(response->fileno)};
        if (!responseUploadFile) return;

        if (response->event < 4 || response->event == 7)
        {
            if (response->event < 0)
            {
                responseUploadFile->uploadFailed(response->event);
                return;
            }

            chunk.pos = -1;

            // also remove from mChunksInFlight - most likely located at the beginning
            for (int i = 0; i < static_cast<int>(mChunksInFlight.size()); i++)
            {
                if (mChunksInFlight[i].first.pos == response->chunkpos && mChunksInFlight[i].first.fileno == response->fileno)
                {
                    chunk = mChunksInFlight[i].first;
                    mChunksInFlight[i].second.apply(chunk.pos, responseUploadFile->mChunkedEncryptMAC, responseUploadFile->mFingerprint);
                    mChunksInFlight.erase(mChunksInFlight.begin() + i);
                    mPool->mNumChunksInFlight--;
                    break;
                }
            }

            if (chunk.pos < 0)
            {
                std::cout << "WsUpload: PROTOCOL ERROR - Server confirmed chunk not in flight: pos=" << chunk.pos << " fileno=" << chunk.fileno << " type=" << response->event << std::endl;
                return;
            }
        }

        if (len == 13)
        {
            responseUploadFile->uploadFailed(response->event);
            return;
        }
        else switch (response->event)
        {
            case 1:     // non-final chunk ingested by server
                if (chunk.len)
                {
                    responseUploadFile->mBytesConfirmed += chunk.len;

                    if (responseUploadFile->mBytesConfirmed >= responseUploadFile->size)
                    {
                        // server confirmed last chunk (or more) rather than completing upload:
                        // this means that the server has lost its state
                        responseUploadFile->uploadFailed(0);
                        break;
                    }
                }
                // fall through
            case 7:     // final chunk ingested by server - server knows that the file is complete
                g_wsUploadMgr.mPoolMgr.mActiveFiles.insert(responseUploadFile); // progress will be shown
                break;

            case 2:     // chunk already on server (could happen after a reconnect/retry)
                break;

            case 3:     // CRC failed (unlikely on SSL, but very possible on TCP)
                std::cout << "WsUpload: Chunk CRC FAILED on " << mPool->mUrl << std::endl;
                mPool->retryChunk(chunk);
                break;

            case 4:     // upload completed
                // ensure that MAC and fingerprint are complete
                mPool->applyInFlight(response->fileno, &responseUploadFile->mChunkedEncryptMAC, &responseUploadFile->mFingerprint);

                responseUploadFile->showThroughput();
                responseUploadFile->uploadComplete(msg + 14, msg[13]);
                break;

            case 5:     // server in distress - refresh pool target URLs from API
                std::cout << "WsUpload: Server requested a pool refresh" << std::endl;
                g_wsUploadMgr.mPoolMgr.refreshPools();
                break;

            case 6:     // uq too large - stop sending for len seconds
                std::cout << "WsUpload: Server requested sending to pause for " << response->chunkpos << " ms" << std::endl;
                mPool->pauseSending(response->chunkpos / 100 + 1);
                break;

            default:    // ignore unknown messages for compatibility with future protocol features
                std::cout << "WsUpload: Unknown response from server " << response->event << std::endl;
        }
    }
}

// this loop is responsible for maintaining the (standby) WebSocket connections and pumping data during transfers
// (since WebSocket doesn't have an onbufferempty(), we need to busy-loop with adaptive frequency to keep the data flowing)
void WsUploadMgr::uploadMgrThread()
{
    lockMutex();

    for (;;)
    {
        mCurrentTime = SteadyTime::ds();

        mPoolMgr.curlIO();

        // we don't check for dead pools while paused
        if (!mPaused) mPoolMgr.checkPools();
    }
}

// the upload speed is shown as server-confirmed bytes per second, which is
// the least impressive option as it ignores in-flight data, including data
// that is already buffered on the target server.
// however, it has the benefit of not stalling at upload completion.
void WsUploadFile::showThroughput()
{
    if (!mUploadCompletionTime && !mUploadFailedTime && mBytesConfirmed != mLastReportedBytesConfirmed)
    {
        mLastReportedBytesConfirmed = mBytesConfirmed;

        // FIXME: use the SDK's reporting facility
        std::cout << "File " << mCredentials << ": ";
        if (SteadyTime::difference(g_wsUploadMgr.mCurrentTime, mUploadStartTime) <= 0) std::cout << "starting";
        else if (mLastReportedBytesConfirmed < size) std::cout << mLastReportedBytesConfirmed / MB << " MB of " << size / MB << " MB (" << mLastReportedBytesConfirmed / SteadyTime::difference(g_wsUploadMgr.mCurrentTime, mUploadStartTime) * 10 / 1024 << " KB/s)";
        else std::cout << "completing";

        std::cout << std::endl;
    }
}

// returns a WsUploadFile* that can be added to the transfer queue
WsUploadFile* WsUploadMgr::wsUploadFile(int fd, const char* credentials)
{
    return new WsUploadFile(++mNextFileNo, fd, credentials);
}

// this must be called with uploadmutex locked
// only affects _active_ pools
void WsUploadMgr::setNumConn(unsigned char numConn)
{
    mPoolMgr.setNumConn(numConn);
}

WsConn::WsConn(WsPool* pool) :
    mPool(pool)
{
    // register with the WsPool
    mConns_it = pool->mConns.insert(this).first;
}

WsConn::~WsConn()
{
    std::cout << "Connection to " << mPool->mUrl << " shutting down" << std::endl;

    mPool->mConns.erase(mConns_it);
    if (curl) curl_easy_cleanup(curl);
}

int main(int argc, char** argv)
{
    curl_global_init(CURL_GLOBAL_ALL);

    std::cout << "MEGA WebSocket Upload Demo" << std::endl;
    std::cout << "Enter a filename to upload it" << std::endl;
    std::cout << "Enter :x to set the number of parallel connections to x" << std::endl;
    std::cout << ":p to pause all uploads, :u to unpause" << std::endl << std::endl;

    g_wsUploadMgr.startUp();

    char filename[1024];

    // read filenames from stdin and upload them
    // entering :number will change the number of parallel connections
    g_wsUploadMgr.unlockMutex();
    while (fgets(filename, sizeof filename, stdin))
    {
        g_wsUploadMgr.lockMutex();

        char* ptr {strchr(filename, 0)};

        if (ptr > filename + 1 && ptr[-1] == '\n')
        {
            ptr[-1] = 0;

            if (*filename == ':')
            {
                switch (filename[1])
                {
                    case 'r':
                        std::cerr << "Refreshing pools..." << std::endl;
                        g_wsUploadMgr.mPoolMgr.refreshPools();
                        break;

                    case 'p':
                        g_wsUploadMgr.pauseAll();
                        std::cerr << "All uploads paused" << std::endl;
                        break;

                    case 'u':
                        g_wsUploadMgr.unpauseAll();
                        std::cerr << "All uploads resumed" << std::endl;
                        break;

                    default:
                        unsigned char numconn = atoi(filename + 1);

                        if (numconn)
                        {
                            std::cerr << "Now using " << (int)numconn << " parallel connections..." << std::endl;
                            g_wsUploadMgr.setNumConn(numconn);
                        }
                }
            }
            else
            {
                int fd {open(filename, O_RDONLY)};

                if (fd < 0) std::cerr << "Can't open " << filename << " (" << errno << ")" << std::endl;
                else
                {
                    std::cerr << "Queued " << filename << " for uploading..." << std::endl;

                    WsUploadFile* wsfile {g_wsUploadMgr.wsUploadFile(fd, filename)};
                    g_wsUploadMgr.mTransferQueue.add(wsfile);
                }
            }
        }

        g_wsUploadMgr.unlockMutex();
    }
}
