package main

import (
	"flag"

	"zatrano/configs/configsdatabase"
	"zatrano/configs/configslog"
	"zatrano/database"
)

func main() {
	configslog.InitLogger()
	defer configslog.SyncLogger()
	migrateFlag := flag.Bool("migrate", false, "Veritabanı başlatma işlemini çalıştır (migrasyonları içerir)")
	seedFlag := flag.Bool("seed", false, "Veritabanı başlatma işlemini çalıştır (seederları içerir)")
	flag.Parse()

	configsdatabase.InitDB()
	defer configsdatabase.CloseDB()

	db := configsdatabase.GetDB()

	configslog.SLog.Info("Veritabanı başlatma işlemi çalıştırılıyor...")
	database.Initialize(db, *migrateFlag, *seedFlag)

	configslog.SLog.Info("Veritabanı başlatma işlemi tamamlandı.")
}
