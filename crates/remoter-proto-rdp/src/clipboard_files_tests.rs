//! Tests for files over the clipboard, against real folders in a scratch
//! directory: the walk that builds an offer, the reads that answer the server,
//! and the save that writes what the server offers.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code, per the workspace convention"
)]

use super::*;

fn write(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

fn names(files: &LocalFileSet) -> Vec<String> {
    files
        .descriptors()
        .iter()
        .map(|descriptor| match &descriptor.relative_path {
            Some(relative) => format!("{relative}\\{}", descriptor.name),
            None => descriptor.name.clone(),
        })
        .collect()
}

fn range(stream_id: u32, index: i32, position: u64, requested_size: u32) -> FileContentsRequest {
    FileContentsRequest {
        stream_id,
        index,
        flags: FileContentsFlags::RANGE,
        position,
        requested_size,
        data_id: None,
    }
}

#[tokio::test]
async fn a_copied_folder_is_offered_parents_first_in_name_order() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path().join("project");
    write(&root.join("b.txt"), b"bee");
    write(&root.join("a").join("inner.txt"), b"inner");
    write(&root.join("a").join("deeper").join("x.bin"), &[1, 2, 3]);
    let single = scratch.path().join("notes.md");
    write(&single, b"# notes");

    let files = LocalFileSet::collect(&[root.display().to_string(), single.display().to_string()])
        .await
        .unwrap();

    assert_eq!(
        names(&files),
        [
            "project",
            "project\\a",
            "project\\b.txt",
            "project\\a\\deeper",
            "project\\a\\inner.txt",
            "project\\a\\deeper\\x.bin",
            "notes.md",
        ]
    );
    let descriptors = files.descriptors();
    assert!(
        descriptors[0]
            .attributes
            .unwrap()
            .contains(ClipboardFileAttributes::DIRECTORY)
    );
    assert_eq!(descriptors[0].file_size, None);
    assert_eq!(descriptors[2].file_size, Some(3));
    assert!(descriptors[2].last_write_time.is_some());
    assert_eq!(files.skipped(), 0);
}

#[tokio::test]
async fn the_same_files_are_the_same_offer_and_a_change_is_a_new_one() {
    let scratch = tempfile::tempdir().unwrap();
    let file = scratch.path().join("report.pdf");
    write(&file, b"v1");
    let paths = [file.display().to_string()];
    let first = LocalFileSet::collect(&paths).await.unwrap().identity();
    assert_eq!(
        first,
        LocalFileSet::collect(&paths).await.unwrap().identity()
    );

    write(&file, b"version two");
    assert_ne!(
        first,
        LocalFileSet::collect(&paths).await.unwrap().identity()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_link_inside_a_copied_folder_is_not_followed() {
    // A folder holding a link to `~/.ssh` must not send `~/.ssh`.
    let scratch = tempfile::tempdir().unwrap();
    let secret = scratch.path().join("secret");
    write(&secret.join("id_ed25519"), b"PRIVATE");
    let copied = scratch.path().join("copied");
    write(&copied.join("readme.txt"), b"hello");
    std::os::unix::fs::symlink(&secret, copied.join("ssh")).unwrap();
    std::os::unix::fs::symlink(secret.join("id_ed25519"), copied.join("key")).unwrap();

    let files = LocalFileSet::collect(&[copied.display().to_string()])
        .await
        .unwrap();
    assert_eq!(names(&files), ["copied", "copied\\readme.txt"]);
    assert_eq!(files.skipped(), 2);
}

#[cfg(unix)]
#[tokio::test]
async fn a_name_the_wire_would_misread_is_left_out_rather_than_shifting_the_index() {
    // `\` is the wire's separator, and `C:x` is read as an absolute path and
    // dropped by `ironrdp-cliprdr` after the list is built — which would move
    // every later index onto the wrong file.
    let scratch = tempfile::tempdir().unwrap();
    let folder = scratch.path().join("mixed");
    write(&folder.join("a\\b.txt"), b"x");
    write(&folder.join("C:x"), b"x");
    write(&folder.join("ok.txt"), b"x");

    let files = LocalFileSet::collect(&[folder.display().to_string()])
        .await
        .unwrap();
    assert_eq!(names(&files), ["mixed", "mixed\\ok.txt"]);
    assert_eq!(files.skipped(), 2);
}

#[tokio::test]
async fn a_folder_with_too_much_in_it_is_refused_whole() {
    let scratch = tempfile::tempdir().unwrap();
    let folder = scratch.path().join("many");
    std::fs::create_dir_all(&folder).unwrap();
    for n in 0..=MAX_LOCAL_ENTRIES {
        std::fs::write(folder.join(format!("{n}.txt")), b"").unwrap();
    }
    let refused = LocalFileSet::collect(&[folder.display().to_string()]).await;
    assert!(matches!(refused, Err(WARNING_FILES_TOO_MANY)));
}

#[tokio::test]
async fn the_server_reads_only_what_was_offered_and_the_end_is_reported_once() {
    let scratch = tempfile::tempdir().unwrap();
    let folder = scratch.path().join("docs");
    let body: Vec<u8> = (0..=255u8).cycle().take(10_000).collect();
    write(&folder.join("data.bin"), &body);
    let files = LocalFileSet::collect(&[folder.display().to_string()])
        .await
        .unwrap();
    let mut open = None;

    // Index 0 is the folder; index 2 does not exist.
    for index in [0, 2, -1] {
        let (response, sent) = files.serve(&range(1, index, 0, 16), &mut open).await;
        assert!(response.is_error(), "index {index}");
        assert!(sent.is_none());
    }

    let size = FileContentsRequest {
        stream_id: 2,
        index: 1,
        flags: FileContentsFlags::SIZE,
        position: 0,
        requested_size: 8,
        data_id: None,
    };
    let (response, _) = files.serve(&size, &mut open).await;
    assert_eq!(response.data_as_size().unwrap(), 10_000);

    let (first, sent) = files.serve(&range(3, 1, 0, 6000), &mut open).await;
    assert_eq!(first.data(), &body[..6000]);
    assert!(sent.is_none());
    let (rest, sent) = files.serve(&range(4, 1, 6000, 6000), &mut open).await;
    assert_eq!(rest.data(), &body[6000..]);
    assert!(matches!(
        sent,
        Some(ClipboardFiles::Sent { bytes: 10_000, .. })
    ));

    // Pasted a second time: served again, reported once.
    let (again, sent) = files.serve(&range(5, 1, 6000, 6000), &mut open).await;
    assert_eq!(again.data(), &body[6000..]);
    assert!(sent.is_none());
}

#[tokio::test]
async fn a_request_for_more_than_the_ceiling_is_answered_with_the_ceiling() {
    let scratch = tempfile::tempdir().unwrap();
    let file = scratch.path().join("big.bin");
    let body = vec![7u8; usize::try_from(MAX_SERVE_BYTES).unwrap() + 1024];
    write(&file, &body);
    let files = LocalFileSet::collect(&[file.display().to_string()])
        .await
        .unwrap();
    let (response, _) = files.serve(&range(1, 0, 0, u32::MAX), &mut None).await;
    assert_eq!(
        response.data().len(),
        usize::try_from(MAX_SERVE_BYTES).unwrap()
    );
}

#[test]
fn a_remote_name_becomes_one_harmless_local_name() {
    assert_eq!(local_component("report.pdf"), "report.pdf");
    assert_eq!(local_component("a:b|c?d*e"), "a_b_c_d_e");
    assert_eq!(local_component("new\nline"), "new_line");
    assert_eq!(local_component("trailing. . "), "trailing");
    assert_eq!(local_component("..."), "_");
    assert_eq!(local_component("CON"), "_CON");
    assert_eq!(local_component("nul.txt"), "_nul.txt");
    assert_eq!(local_component("console.log"), "console.log");
}

#[test]
fn a_taken_name_gets_a_number_before_its_extension() {
    assert_eq!(numbered("report.pdf", 2), "report (2).pdf");
    assert_eq!(numbered("logs", 3), "logs (3)");
    assert_eq!(numbered(".profile", 2), ".profile (2)");
}

fn remote(name: &str, relative: Option<&str>, size: Option<u64>) -> FileDescriptor {
    let mut descriptor = FileDescriptor::new(name);
    if let Some(relative) = relative {
        descriptor = descriptor.with_relative_path(relative);
    }
    match size {
        Some(size) => descriptor
            .with_attributes(ClipboardFileAttributes::ARCHIVE)
            .with_file_size(size),
        None => descriptor.with_attributes(ClipboardFileAttributes::DIRECTORY),
    }
}

/// Answers every request a save makes from `contents`, the way a server would,
/// in pieces no larger than it was asked for.
async fn run_save(
    job: &mut SaveJob,
    contents: &[Vec<u8>],
) -> (Result<ClipboardFiles, &'static str>, Vec<ClipboardFiles>) {
    let mut events = Vec::new();
    let mut step = job.advance(&mut events).await;
    loop {
        match step {
            Ok(SaveStep::Finished(done)) => return (Ok(done), events),
            Err(reason) => return (Err(reason), events),
            Ok(SaveStep::Request(request)) => {
                assert!(job.expects(request.stream_id));
                let file = &contents[usize::try_from(request.index).unwrap()];
                let reply = if request.flags.contains(FileContentsFlags::SIZE) {
                    (file.len() as u64).to_le_bytes().to_vec()
                } else {
                    let start = usize::try_from(request.position).unwrap();
                    let end = (start + request.requested_size as usize).min(file.len());
                    file[start..end].to_vec()
                };
                step = job.receive(Some(&reply), &mut events).await;
            }
        }
    }
}

#[tokio::test]
async fn a_save_writes_every_file_whole_and_numbers_what_is_already_there() {
    let scratch = tempfile::tempdir().unwrap();
    let target = scratch.path();
    write(&target.join("Reports").join("keep.txt"), b"mine");

    let big: Vec<u8> = (0..3 * SAVE_CHUNK_BYTES + 17).map(|n| n as u8).collect();
    let list = [
        remote("Reports", None, None),
        remote("q1.xlsx", Some("Reports"), Some(big.len() as u64)),
        remote("empty.txt", Some("Reports"), Some(0)),
        remote("unknown-size.log", None, None).with_attributes(ClipboardFileAttributes::ARCHIVE),
    ];
    let contents = vec![Vec::new(), big.clone(), Vec::new(), b"sized later".to_vec()];

    let mut job = SaveJob::plan(target, &list, Some(7)).await.unwrap();
    let (outcome, events) = run_save(&mut job, &contents).await;
    let Ok(ClipboardFiles::Finished { files, bytes, .. }) = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(files, 3);
    assert_eq!(bytes, big.len() as u64 + 11);

    // The folder that was already there is untouched, and the new one is
    // numbered beside it.
    assert_eq!(
        std::fs::read(target.join("Reports").join("keep.txt")).unwrap(),
        b"mine"
    );
    assert_eq!(
        std::fs::read(target.join("Reports (2)").join("q1.xlsx")).unwrap(),
        big
    );
    assert_eq!(
        std::fs::read(target.join("Reports (2)").join("empty.txt")).unwrap(),
        b""
    );
    assert_eq!(
        std::fs::read(target.join("unknown-size.log")).unwrap(),
        b"sized later"
    );
    // Nothing temporary is left behind.
    let leftovers: Vec<_> = walkdir(target)
        .into_iter()
        .filter(|path| path.to_string_lossy().ends_with(PART_SUFFIX))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    let saved: Vec<&str> = events
        .iter()
        .filter_map(|event| match event {
            ClipboardFiles::Saved { remote, .. } => Some(remote.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        saved,
        ["Reports/q1.xlsx", "Reports/empty.txt", "unknown-size.log"]
    );
}

fn walkdir(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path.clone());
            }
            out.push(path);
        }
    }
    out
}

#[tokio::test]
async fn a_hostile_list_cannot_write_outside_the_chosen_folder() {
    let scratch = tempfile::tempdir().unwrap();
    let target = scratch.path().join("inbox");
    std::fs::create_dir_all(&target).unwrap();
    // What `ironrdp-cliprdr` would hand over after its own sanitising, plus
    // what it leaves for this side: reserved characters and device names.
    let list = [
        remote("..", Some("etc"), Some(1)),
        remote("CON", None, Some(1)),
        remote("x:y", Some("a|b"), Some(1)),
    ];
    let contents = vec![b"1".to_vec(), b"2".to_vec(), b"3".to_vec()];
    let mut job = SaveJob::plan(&target, &list, None).await.unwrap();
    let (outcome, _) = run_save(&mut job, &contents).await;
    assert!(matches!(
        outcome,
        Ok(ClipboardFiles::Finished { files: 3, .. })
    ));

    for path in walkdir(scratch.path()) {
        assert!(path.starts_with(&target), "{path:?} escaped");
    }
    assert!(target.join("etc").join("_").exists());
    assert!(target.join("_CON").exists());
    assert!(target.join("a_b").join("x_y").exists());
}

#[tokio::test]
async fn a_server_that_stops_sending_fails_the_save_and_leaves_no_partial_file() {
    let scratch = tempfile::tempdir().unwrap();
    let list = [remote(
        "movie.mkv",
        None,
        Some(4 * u64::from(SAVE_CHUNK_BYTES)),
    )];
    let mut job = SaveJob::plan(scratch.path(), &list, None).await.unwrap();
    let mut events = Vec::new();
    let Ok(SaveStep::Request(_)) = job.advance(&mut events).await else {
        panic!("the save did not ask for the file");
    };
    let chunk = vec![0u8; SAVE_CHUNK_BYTES as usize];
    let Ok(SaveStep::Request(_)) = job.receive(Some(&chunk), &mut events).await else {
        panic!("the save did not ask for the rest");
    };
    assert!(
        scratch
            .path()
            .join(format!("movie.mkv{PART_SUFFIX}"))
            .exists()
    );

    // An empty answer before the end would be asked again for ever.
    assert!(matches!(
        job.receive(Some(&[]), &mut events).await,
        Err(SAVE_REFUSED)
    ));
    job.abandon().await;
    assert!(walkdir(scratch.path()).is_empty());
}

#[tokio::test]
async fn bytes_past_the_declared_size_are_not_written() {
    let scratch = tempfile::tempdir().unwrap();
    let list = [remote("small.txt", None, Some(4))];
    let mut job = SaveJob::plan(scratch.path(), &list, None).await.unwrap();
    let mut events = Vec::new();
    let _ = job.advance(&mut events).await;
    let outcome = job.receive(Some(b"abcdefgh"), &mut events).await;
    assert!(matches!(outcome, Ok(SaveStep::Finished(_))));
    assert_eq!(
        std::fs::read(scratch.path().join("small.txt")).unwrap(),
        b"abcd"
    );
}

#[tokio::test]
async fn a_folder_that_is_not_there_is_refused_before_anything_is_asked() {
    let scratch = tempfile::tempdir().unwrap();
    let missing = scratch.path().join("gone");
    let list = [remote("a.txt", None, Some(1))];
    assert!(matches!(
        SaveJob::plan(&missing, &list, None).await,
        Err(SAVE_WRITE_FAILED)
    ));
    assert!(matches!(
        SaveJob::plan(scratch.path(), &[], None).await,
        Err(SAVE_NOTHING)
    ));
}

#[test]
fn an_offer_names_the_first_entries_and_counts_them_all() {
    let mut list = vec![remote("folder", None, None)];
    for n in 0..150 {
        list.push(remote(&format!("{n}.bin"), Some("folder"), Some(10)));
    }
    let ClipboardFiles::Offered {
        files,
        total_entries,
        total_bytes,
    } = offered(&list)
    else {
        panic!("not an offer");
    };
    assert_eq!(files.len(), OFFERED_LISTED);
    assert_eq!(total_entries, 151);
    assert_eq!(total_bytes, 1500);
    assert!(files[0].directory);
    assert_eq!(files[1].path, "folder/0.bin");
    assert_eq!(files[1].size, Some(10));
}

#[test]
fn nothing_here_debug_prints_a_path() {
    let offer = offered(&[remote("salaries-2026.xlsx", None, Some(1))]);
    assert!(!format!("{offer:?}").contains("salaries"));
    let saved = ClipboardFiles::Saved {
        remote: "salaries-2026.xlsx".to_owned(),
        local: "/home/ada/salaries-2026.xlsx".to_owned(),
        bytes: 1,
    };
    assert!(!format!("{saved:?}").contains("salaries"));
}
