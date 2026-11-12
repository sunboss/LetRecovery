//! Native system-restore page.
//!
//! This module only presents and collects restore intent. Starting a restore remains the
//! controller's responsibility so a window notification can never directly perform disk I/O.
//! The page mirrors the backup page's structure: a file picker for the backup image, a combo
//! fed by the verified image catalog, and the shared partition inventory as the target list.

use std::cell::{Cell, RefCell};

use windows::core::{w, PCWSTR, PWSTR};
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, WPARAM};
use windows::Win32::Graphics::Gdi::HFONT;
use windows::Win32::UI::Controls::{
    LVCF_TEXT, LVCF_WIDTH, LVCOLUMNW, LVIF_TEXT, LVIS_SELECTED, LVITEMW, LVM_DELETEALLITEMS,
    LVM_GETNEXTITEM, LVM_INSERTCOLUMNW, LVM_INSERTITEMW, LVM_SETBKCOLOR,
    LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETITEMSTATE, LVM_SETTEXTBKCOLOR, LVM_SETTEXTCOLOR,
    LVS_EX_DOUBLEBUFFER, LVS_EX_FULLROWSELECT, LVS_REPORT, LVS_SHOWSELALWAYS,
};
use windows::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, GetWindowTextLengthW, GetWindowTextW, SendMessageW, ShowWindow, BS_OWNERDRAW,
    CBS_DROPDOWNLIST, CB_ADDSTRING, CB_GETCURSEL, CB_RESETCONTENT, CB_SETCURSEL, ES_AUTOHSCROLL,
    HMENU, SW_HIDE, SW_SHOW, WINDOW_EX_STYLE, WINDOW_STYLE, WM_SETFONT, WS_CHILD, WS_TABSTOP,
};

use super::super::controls::{child, move_layout_window as MoveWindow, wide};
use super::super::layout::{centered_control_y_ceil, measure_text, LayoutMetrics};
use super::super::theme::{
    apply_control_theme, apply_list_view_theme, combo_closed_height, NativeControlKind, Palette,
};
use super::backup::BackupPartitionRow;
use crate::core::install_config::RestoreConfig;

pub const ID_IMAGE_PATH: u16 = 430;
pub const ID_BROWSE: u16 = 431;
pub const ID_IMAGE_LIST: u16 = 432;
pub const ID_TARGET_LIST: u16 = 433;

/// One verified catalog entry shown in the image combo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreImageEntry {
    pub index: u32,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RestorePageState {
    pub image_path: String,
    /// WIM image index selected in the catalog combo; 0 means no verified entry is selected.
    pub image_index: u32,
    pub target_partition: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreValidationError {
    ImagePathRequired,
    ImageEntryRequired,
    TargetPartitionRequired,
    TargetPartitionUnavailable { index: usize },
    TargetPartitionInvalid,
}

impl std::fmt::Display for RestoreValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ImagePathRequired => formatter.write_str(&crate::tr!("请选择备份镜像文件")),
            Self::ImageEntryRequired => formatter.write_str(&crate::tr!("请选择要还原的映像")),
            Self::TargetPartitionRequired => {
                formatter.write_str(&crate::tr!("请选择要还原到的分区"))
            }
            Self::TargetPartitionUnavailable { .. } => {
                formatter.write_str(&crate::tr!("所选目标分区已不可用，请重新选择"))
            }
            Self::TargetPartitionInvalid => {
                formatter.write_str(&crate::tr!("所选目标分区没有有效盘符"))
            }
        }
    }
}

impl std::error::Error for RestoreValidationError {}

impl RestorePageState {
    pub fn validate(
        &self,
        partitions: &[BackupPartitionRow],
    ) -> Result<(), RestoreValidationError> {
        if self.image_path.trim().is_empty() {
            return Err(RestoreValidationError::ImagePathRequired);
        }
        if self.image_index == 0 {
            return Err(RestoreValidationError::ImageEntryRequired);
        }
        let index = self
            .target_partition
            .ok_or(RestoreValidationError::TargetPartitionRequired)?;
        let partition = partitions
            .get(index)
            .ok_or(RestoreValidationError::TargetPartitionUnavailable { index })?;
        if partition.volume.trim().is_empty() {
            return Err(RestoreValidationError::TargetPartitionInvalid);
        }
        Ok(())
    }

    /// Converts validated UI intent to the existing PE-compatible configuration model.
    /// This is a pure conversion: it does not write configuration or start a restore.
    pub fn to_restore_config(
        &self,
        partitions: &[BackupPartitionRow],
        image_name: &str,
        image_description: &str,
        wim_engine: u8,
    ) -> Result<RestoreConfig, RestoreValidationError> {
        self.validate(partitions)?;
        let index = self
            .target_partition
            .ok_or(RestoreValidationError::TargetPartitionRequired)?;
        let partition = partitions
            .get(index)
            .ok_or(RestoreValidationError::TargetPartitionUnavailable { index })?;
        Ok(RestoreConfig {
            image_path: self.image_path.trim().to_owned(),
            target_partition: partition.volume.trim().to_owned(),
            image_index: self.image_index,
            image_name: image_name.to_owned(),
            image_description: image_description.to_owned(),
            wim_engine,
            handoff: None,
        })
    }
}

pub fn target_warning_text(partitions: &[BackupPartitionRow], selected: Option<usize>) -> String {
    match selected.and_then(|index| partitions.get(index)) {
        Some(partition) if !partition.has_windows => {
            crate::tr!("所选分区似乎没有 Windows 系统")
        }
        Some(partition) if partition.is_system_partition => {
            crate::tr!("还原将覆盖当前系统分区上的全部数据，请确认已备份重要文件。")
        }
        Some(_) => crate::tr!("还原将覆盖所选分区上的全部数据。"),
        None => crate::tr!("请选择备份镜像和要还原到的分区。"),
    }
}

#[derive(Clone, Copy)]
pub struct RestorePageHandles {
    pub image_label: HWND,
    pub image_path: HWND,
    pub browse: HWND,
    pub image_list_label: HWND,
    pub image_list: HWND,
    pub target_label: HWND,
    pub target_list: HWND,
    pub warning: HWND,
}

pub struct RestorePage {
    handles: RestorePageHandles,
    font: Cell<HFONT>,
    images: RefCell<Vec<RestoreImageEntry>>,
}

impl RestorePage {
    /// Creates a hidden page. Call `layout`, `apply_theme`, `apply_font`, then `show(true)`.
    pub unsafe fn create(
        parent: HWND,
        partitions: &[BackupPartitionRow],
        initial: &RestorePageState,
    ) -> windows::core::Result<Self> {
        let image_label = child(parent, w!("STATIC"), &crate::tr!("备份镜像:"), 0, 434)?;
        let image_path = edit(parent, ID_IMAGE_PATH, &initial.image_path)?;
        let browse = child(
            parent,
            w!("BUTTON"),
            &crate::tr!("浏览..."),
            BS_OWNERDRAW | WS_TABSTOP.0 as i32,
            ID_BROWSE,
        )?;
        let image_list_label = child(parent, w!("STATIC"), &crate::tr!("选择映像:"), 0, 435)?;
        let image_list = child(
            parent,
            w!("COMBOBOX"),
            "",
            CBS_DROPDOWNLIST | WS_TABSTOP.0 as i32,
            ID_IMAGE_LIST,
        )?;
        let target_label = child(
            parent,
            w!("STATIC"),
            &crate::tr!("选择要还原到的分区:"),
            0,
            436,
        )?;
        let target_list = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("SysListView32"),
            w!(""),
            WINDOW_STYLE((WS_CHILD | WS_TABSTOP).0 | LVS_REPORT | LVS_SHOWSELALWAYS),
            0,
            0,
            0,
            0,
            parent,
            HMENU(ID_TARGET_LIST as isize as *mut _),
            HINSTANCE::default(),
            None,
        )?;
        let _ = SendMessageW(
            target_list,
            LVM_SETEXTENDEDLISTVIEWSTYLE,
            WPARAM(0),
            LPARAM((LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER) as isize),
        );
        let warning = child(
            parent,
            w!("STATIC"),
            &crate::tr!("请选择备份镜像和要还原到的分区。"),
            0,
            437,
        )?;
        let page = Self {
            handles: RestorePageHandles {
                image_label,
                image_path,
                browse,
                image_list_label,
                image_list,
                target_label,
                target_list,
                warning,
            },
            font: Cell::new(HFONT::default()),
            images: RefCell::new(Vec::new()),
        };
        page.populate_partitions(partitions, initial.target_partition, true);
        page.show(false);
        Ok(page)
    }

    pub const fn handles(&self) -> RestorePageHandles {
        self.handles
    }

    pub unsafe fn set_image_path(&self, path: &str) {
        set_text(self.handles.image_path, path);
    }

    /// Replaces the catalog combo contents after the window verified the selected image file.
    pub unsafe fn set_image_entries(&self, entries: Vec<RestoreImageEntry>) {
        let combo = self.handles.image_list;
        let _ = SendMessageW(combo, CB_RESETCONTENT, WPARAM(0), LPARAM(0));
        for entry in &entries {
            let label = wide(format!("{} - {}", entry.index, entry.name));
            let _ = SendMessageW(
                combo,
                CB_ADDSTRING,
                WPARAM(0),
                LPARAM(label.as_ptr() as isize),
            );
        }
        if !entries.is_empty() {
            let _ = SendMessageW(combo, CB_SETCURSEL, WPARAM(0), LPARAM(0));
        }
        *self.images.borrow_mut() = entries;
    }

    pub fn image_entries(&self) -> Vec<RestoreImageEntry> {
        self.images.borrow().clone()
    }

    pub unsafe fn relocalize(&self) {
        let h = self.handles;
        set_text(h.image_label, &crate::tr!("备份镜像:"));
        set_text(h.browse, &crate::tr!("浏览..."));
        set_text(h.image_list_label, &crate::tr!("选择映像:"));
        set_text(h.target_label, &crate::tr!("选择要还原到的分区:"));
        for (index, title) in [
            crate::tr!("分区卷"),
            crate::tr!("总空间"),
            crate::tr!("已用空间"),
            crate::tr!("卷标"),
            "BitLocker".to_owned(),
            crate::tr!("状态"),
        ]
        .into_iter()
        .enumerate()
        {
            let mut title = wide(&title);
            let mut column = LVCOLUMNW {
                mask: LVCF_TEXT,
                pszText: PWSTR(title.as_mut_ptr()),
                ..Default::default()
            };
            let _ = SendMessageW(
                h.target_list,
                0x1060,
                WPARAM(index),
                LPARAM((&mut column as *mut LVCOLUMNW) as isize),
            );
        }
    }

    /// Refreshes the visible inventory after the controller has matched a prior selection
    /// against the newly enumerated stable partition identity.
    pub unsafe fn replace_partitions(
        &self,
        partitions: &[BackupPartitionRow],
        selected: Option<usize>,
    ) {
        self.populate_partitions(partitions, selected, false);
    }

    /// Refreshes the target warning after selection or inventory changes.
    pub unsafe fn update_target_warning(&self, partitions: &[BackupPartitionRow]) {
        let selected = self.read_state().target_partition;
        let message = target_warning_text(partitions, selected);
        set_text(self.handles.warning, &message);
    }

    /// Positions the page within the caller's content rectangle using logical 96-DPI units.
    pub unsafe fn layout(&self, left: i32, top: i32, width: i32, dpi: u32) {
        let s = |value: i32| value * dpi as i32 / 96;
        let h = self.handles;
        let width = width.max(0);
        let font = self.font.get();
        let measured_label_widths = [
            (h.image_label, crate::tr!("备份镜像:")),
            (h.image_list_label, crate::tr!("选择映像:")),
        ]
        .map(|(control, label)| measure_text(control, font, &label, None).width);
        let label_width = restore_label_column_width(&measured_label_widths, width, dpi);
        let metrics = LayoutMetrics::for_dpi(dpi);
        let row_height = metrics.field_height.max(metrics.button_height);

        let image_top = top;
        let label_y = centered_control_y_ceil(image_top, row_height, metrics.label_height);
        move_control(
            h.image_label,
            left,
            label_y,
            label_width,
            metrics.label_height,
        );
        let browse_width = s(88);
        let edit_width = (width - label_width - browse_width - s(8)).max(0);
        move_control(
            h.image_path,
            left + label_width,
            image_top,
            edit_width,
            row_height,
        );
        move_control(
            h.browse,
            left + label_width + edit_width + s(8),
            image_top,
            browse_width,
            row_height,
        );

        let combo_top = image_top + row_height + s(10);
        let combo_closed_height = combo_closed_height(h.image_list, metrics.field_height);
        let combo_row_height = combo_closed_height.max(metrics.field_height);
        let combo_label_y =
            centered_control_y_ceil(combo_top, combo_row_height, metrics.label_height);
        move_control(
            h.image_list_label,
            left,
            combo_label_y,
            label_width,
            metrics.label_height,
        );
        move_control(
            h.image_list,
            left + label_width,
            combo_top,
            (width - label_width).max(0),
            combo_row_height,
        );

        let target_label_top = combo_top + combo_row_height + s(14);
        move_control(
            h.target_label,
            left,
            target_label_top,
            width,
            metrics.label_height,
        );
        let table_top = target_label_top + s(26);
        let table_height = s(150);
        move_control(h.target_list, left, table_top, width, table_height);
        for (column, column_width) in restore_column_widths(width, dpi).into_iter().enumerate() {
            let _ = SendMessageW(
                h.target_list,
                0x101E, // LVM_SETCOLUMNWIDTH
                WPARAM(column),
                LPARAM(column_width as isize),
            );
        }

        let warning_top = table_top + table_height + s(10);
        move_control(h.warning, left, warning_top, width, metrics.label_height);
    }

    pub unsafe fn show(&self, visible: bool) {
        let command = if visible { SW_SHOW } else { SW_HIDE };
        for control in self.all_controls() {
            let _ = ShowWindow(control, command);
        }
    }

    pub unsafe fn apply_theme(&self, palette: Palette) {
        let _ = apply_list_view_theme(self.handles.target_list, palette);
        apply_control_theme(self.handles.browse, palette, NativeControlKind::General);
        for control in [self.handles.image_path, self.handles.image_list] {
            apply_control_theme(control, palette, NativeControlKind::Field);
        }
        for (message, color) in [
            (LVM_SETBKCOLOR, palette.edit),
            (LVM_SETTEXTBKCOLOR, palette.edit),
            (LVM_SETTEXTCOLOR, palette.text),
        ] {
            let _ = SendMessageW(
                self.handles.target_list,
                message,
                WPARAM(0),
                LPARAM(color.0 as isize),
            );
        }
    }

    pub unsafe fn apply_font(&self, font: HFONT) {
        self.font.set(font);
        for control in self.all_controls() {
            let _ = SendMessageW(control, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
        }
    }

    pub unsafe fn read_state(&self) -> RestorePageState {
        let selected = SendMessageW(
            self.handles.target_list,
            LVM_GETNEXTITEM,
            WPARAM(usize::MAX),
            LPARAM(LVIS_SELECTED.0 as isize),
        )
        .0;
        let combo_index =
            SendMessageW(self.handles.image_list, CB_GETCURSEL, WPARAM(0), LPARAM(0)).0;
        let image_index = (combo_index >= 0)
            .then(|| {
                self.images
                    .borrow()
                    .get(combo_index as usize)
                    .map(|entry| entry.index)
            })
            .flatten()
            .unwrap_or(0);
        RestorePageState {
            image_path: read_text(self.handles.image_path),
            image_index,
            target_partition: (selected >= 0).then_some(selected as usize),
        }
    }

    pub unsafe fn set_enabled(&self, enabled: bool) {
        for control in [
            self.handles.image_path,
            self.handles.browse,
            self.handles.image_list,
            self.handles.target_list,
        ] {
            let _ = EnableWindow(control, enabled);
        }
    }

    unsafe fn populate_partitions(
        &self,
        partitions: &[BackupPartitionRow],
        selected: Option<usize>,
        add_columns: bool,
    ) {
        if add_columns {
            let long_state_labels = crate::tr!("未加密").chars().count() > 6;
            for (index, (title, width)) in [
                (crate::tr!("分区卷"), 120),
                (crate::tr!("总空间"), 82),
                (crate::tr!("已用空间"), 82),
                (crate::tr!("卷标"), 94),
                (
                    "BitLocker".to_owned(),
                    if long_state_labels { 120 } else { 92 },
                ),
                (crate::tr!("状态"), if long_state_labels { 148 } else { 80 }),
            ]
            .into_iter()
            .enumerate()
            {
                let mut title = wide(&title);
                let mut column = LVCOLUMNW {
                    mask: LVCF_TEXT | LVCF_WIDTH,
                    cx: width,
                    pszText: PWSTR(title.as_mut_ptr()),
                    ..Default::default()
                };
                let _ = SendMessageW(
                    self.handles.target_list,
                    LVM_INSERTCOLUMNW,
                    WPARAM(index),
                    LPARAM((&mut column as *mut LVCOLUMNW) as isize),
                );
            }
        }
        let _ = SendMessageW(
            self.handles.target_list,
            LVM_DELETEALLITEMS,
            WPARAM(0),
            LPARAM(0),
        );
        for (row, partition) in partitions.iter().enumerate() {
            let volume = if partition.is_system_partition {
                crate::tr!("{} (当前系统)", partition.volume)
            } else {
                partition.volume.clone()
            };
            for (column, value) in [
                volume,
                partition.total_size.clone(),
                partition.used_size.clone(),
                partition.label.clone(),
                partition.bitlocker.clone(),
                partition.status.clone(),
            ]
            .into_iter()
            .enumerate()
            {
                let mut value = wide(value);
                let mut item = LVITEMW {
                    mask: LVIF_TEXT,
                    iItem: row as i32,
                    iSubItem: column as i32,
                    pszText: PWSTR(value.as_mut_ptr()),
                    ..Default::default()
                };
                let message = if column == 0 { LVM_INSERTITEMW } else { 0x104C };
                let _ = SendMessageW(
                    self.handles.target_list,
                    message,
                    WPARAM(0),
                    LPARAM((&mut item as *mut LVITEMW) as isize),
                );
            }
        }
        let selected = selected.or_else(|| {
            partitions
                .iter()
                .position(|partition| partition.is_system_partition)
        });
        if let Some(row) = selected.filter(|row| *row < partitions.len()) {
            let mut item = LVITEMW {
                stateMask: LVIS_SELECTED,
                state: LVIS_SELECTED,
                iItem: row as i32,
                ..Default::default()
            };
            let _ = SendMessageW(
                self.handles.target_list,
                LVM_SETITEMSTATE,
                WPARAM(row),
                LPARAM((&mut item as *mut LVITEMW) as isize),
            );
        }
    }

    fn all_controls(&self) -> [HWND; 8] {
        let h = self.handles;
        [
            h.image_label,
            h.image_path,
            h.browse,
            h.image_list_label,
            h.image_list,
            h.target_label,
            h.target_list,
            h.warning,
        ]
    }
}

fn restore_column_widths(table_width: i32, dpi: u32) -> [i32; 6] {
    let s = |value: i32| value * dpi as i32 / 96;
    let fixed = [s(120), s(82), s(82), s(94), s(92), s(80)];
    let total: i32 = fixed.iter().sum();
    let mut widths = fixed;
    if table_width > total {
        widths[0] += table_width - total;
    }
    widths
}

fn restore_label_column_width(measured_widths: &[i32], available_width: i32, dpi: u32) -> i32 {
    let widest = measured_widths.iter().copied().max().unwrap_or(0);
    let minimum = 72 * dpi as i32 / 96;
    let maximum = (available_width / 2).max(minimum);
    (widest + 8 * dpi as i32 / 96).clamp(minimum, maximum)
}

unsafe fn edit(parent: HWND, id: u16, text: &str) -> windows::core::Result<HWND> {
    child(
        parent,
        w!("EDIT"),
        text,
        WS_TABSTOP.0 as i32 | ES_AUTOHSCROLL,
        id,
    )
}

unsafe fn read_text(hwnd: HWND) -> String {
    let length = GetWindowTextLengthW(hwnd);
    if length <= 0 {
        return String::new();
    }
    let mut buffer = vec![0_u16; length as usize + 1];
    let copied = GetWindowTextW(hwnd, &mut buffer);
    String::from_utf16_lossy(&buffer[..copied as usize])
}

unsafe fn set_text(hwnd: HWND, text: &str) {
    let text = wide(text);
    let _ = windows::Win32::UI::WindowsAndMessaging::SetWindowTextW(hwnd, PCWSTR(text.as_ptr()));
}

unsafe fn move_control(hwnd: HWND, x: i32, y: i32, width: i32, height: i32) {
    let _ = MoveWindow(hwnd, x, y, width.max(0), height.max(0), false);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn partition() -> BackupPartitionRow {
        BackupPartitionRow {
            volume: "C:".to_owned(),
            total_size: "100 GB".to_owned(),
            used_size: "40 GB".to_owned(),
            label: "Windows".to_owned(),
            bitlocker: "未加密".to_owned(),
            status: "已有系统".to_owned(),
            has_windows: true,
            is_system_partition: true,
        }
    }

    #[test]
    fn restore_state_requires_image_entry_and_target() {
        let partitions = [partition()];
        let mut state = RestorePageState {
            image_path: "D:\\RZhuangJi_Backups\\system.wim".to_owned(),
            image_index: 1,
            target_partition: Some(0),
        };
        assert!(state.validate(&partitions).is_ok());
        let config = state
            .to_restore_config(&partitions, "System Backup", "", 0)
            .unwrap();
        assert_eq!(config.target_partition, "C:");
        assert_eq!(config.image_index, 1);

        state.image_index = 0;
        assert_eq!(
            state.validate(&partitions),
            Err(RestoreValidationError::ImageEntryRequired)
        );
        state.image_index = 1;
        state.target_partition = None;
        assert_eq!(
            state.validate(&partitions),
            Err(RestoreValidationError::TargetPartitionRequired)
        );
        state.target_partition = Some(3);
        assert_eq!(
            state.validate(&partitions),
            Err(RestoreValidationError::TargetPartitionUnavailable { index: 3 })
        );
    }

    #[test]
    fn restore_warning_names_the_overwrite_risk() {
        let partitions = [partition()];
        assert!(target_warning_text(&partitions, Some(0)).contains("覆盖"));
        assert!(target_warning_text(&partitions, None).contains("请选择"));
    }
}
