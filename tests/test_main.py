from pc_security.main import main


def test_main_prints_scaffold_message(capsys) -> None:
    main()
    output = capsys.readouterr().out

    assert "PC Security Assistant scaffold is ready." in output
    assert "read-only" in output
