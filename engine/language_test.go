package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestDiagnosticLanguage(t *testing.T) {
	t.Setenv(languageEnvironment, "ru")
	for _, tc := range []struct{ header, lang, heading, route string }{
		{"ru-RU,en;q=0.5", "ru", "Проверка браузера", "Системный DNS → локальная служба"},
		{"de-DE,ru;q=0.8", "en", "Browser check", "System DNS → local service"},
		{"", "ru", "Проверка браузера", "Системный DNS → локальная служба"},
	} {
		lang := browserLanguage(tc.header)
		if lang != tc.lang {
			t.Fatalf("browserLanguage(%q) = %s", tc.header, lang)
		}
		var out bytes.Buffer
		data := struct{ Route, Zone, Language string }{"System DNS → local service", "Etc/UTC", lang}
		if err := checkPage.Execute(&out, data); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{tc.heading, tc.route, `lang="` + lang + `"`, "Etc/UTC"} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("missing %q in %s page", want, lang)
			}
		}
	}
}

func TestProxyErrorLanguage(t *testing.T) {
	for _, tc := range []struct{ lang, want string }{
		{"ru", "неизвестный тип прокси"}, {"en", "unknown proxy type"}, {"hy", "unknown proxy type"},
	} {
		t.Setenv(languageEnvironment, tc.lang)
		if got := message("unknown proxy type"); got != tc.want {
			t.Errorf("message for %s = %q", tc.lang, got)
		}
	}
}
