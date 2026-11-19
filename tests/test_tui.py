from textual.widgets import DataTable, Input

from raven.demo import seed_demo
from raven.tui import RavenApp


async def test_dashboard_filter_details_offline_guard_and_export(tmp_path):
    seed_demo(tmp_path)
    app = RavenApp(tmp_path, demo=True)
    async with app.run_test(size=(130, 42)) as pilot:
        await pilot.pause()
        assert app.query_one("#surface", DataTable).row_count == 9
        app.query_one("#search", Input).value = "api.staging"
        await pilot.pause()
        assert app.query_one("#surface", DataTable).row_count == 1
        app.query_one("#surface", DataTable).focus()
        await pilot.press("enter")
        await pilot.pause()
        assert len(app.screen_stack) == 2
        await pilot.click("#close-detail")
        await pilot.pause()
        assert len(app.screen_stack) == 1
        await pilot.click("#run")
        assert app.scan_task is None
        await pilot.click("#export")
        await pilot.pause()
        assert list((tmp_path / "exports").glob("*/report.json"))


async def test_import_dialog_accepts_local_file(tmp_path):
    seed_demo(tmp_path)
    source = tmp_path / "extra.txt"
    source.write_text("new.atlas.test\nnot-in-scope.test\n")
    app = RavenApp(tmp_path, demo=True)
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.click("#import")
        app.screen.query_one("#file-path", Input).value = str(source)
        await pilot.click("#do-import")
        await pilot.pause()
        assert app.query_one("#surface", DataTable).row_count == 10
