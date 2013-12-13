#include "sctp_chunk_statistics_dialog.h"
#include "ui_sctp_chunk_statistics_dialog.h"
#include "uat_dialog.h"

#include <string>


SCTPChunkStatisticsDialog::SCTPChunkStatisticsDialog(QWidget *parent, sctp_assoc_info_t *assoc, capture_file *cf) :
    QDialog(parent),
    ui(new Ui::SCTPChunkStatisticsDialog),
    selected_assoc(assoc),
    cap_file_(cf)
{
    ui->setupUi(this);
    printf("selected_assoc id=%d\n", selected_assoc->assoc_id);
#if (QT_VERSION < QT_VERSION_CHECK(5, 0, 0))
    ui->tableWidget->verticalHeader()->setClickable(true);
    ui->tableWidget->verticalHeader()->setMovable(true);
#else
    ui->tableWidget->verticalHeader()->setSectionsClickable(true);
    ui->tableWidget->verticalHeader()->setSectionsMovable(true);
#endif


    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);

#if (QT_VERSION < QT_VERSION_CHECK(5, 0, 0))
    ui->tableWidget->horizontalHeader()->setResizeMode(QHeaderView::ResizeToContents);
#else
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
#endif

    this->setWindowTitle(QString("SCTP Chunk Statistics: %1 Port1 %2 Port2 %3").arg(cf_get_display_name(cap_file_)).arg(selected_assoc->port1).arg(selected_assoc->port2));
   // connect(ui->tableWidget->verticalHeader(), SIGNAL(sectionClicked(int)), this, SLOT(on_sectionClicked(int)));
    connect(ui->tableWidget->verticalHeader(), SIGNAL(sectionMoved(int,int,int)), this, SLOT(on_sectionMoved(int, int, int)));

    ctx_menu_.addAction(ui->actionHideChunkType);
    ctx_menu_.addAction(ui->actionChunkTypePreferences);
    ctx_menu_.addAction(ui->actionShowAllChunkTypes);
    initializeChunkMap();
    fillTable();
}

SCTPChunkStatisticsDialog::~SCTPChunkStatisticsDialog()
{
    delete ui;
}

void SCTPChunkStatisticsDialog::initializeChunkMap()
{
    struct chunkTypes temp;
    gchar buf[16];

    for (int i = 0; i < 256; i++) {
        temp.id = i;
        temp.row = i;
        sprintf(buf, "%d", i);
        strcpy(temp.name, val_to_str_const(i, chunk_type_values, "NA"));
        if (strcmp(temp.name, "NA") == 0) {
            temp.hide = 1;
            strcpy(temp.name, buf);
        } else {
            temp.hide = 0;
        }
        chunks.insert(i, temp);
    }
}

void SCTPChunkStatisticsDialog::fillTable(bool all)
{
    FILE* fp;

    pref_t *pref = prefs_find_preference(prefs_find_module("sctp"),"statistics_chunk_types");
    uat_t *uat = pref->varp.uat;
    gchar* fname = uat_get_actual_filename(uat,TRUE);
    bool init = false;

    if (!fname ) {
        printf("no filename\n");
        init = true;
    } else {
        fp = ws_fopen(fname,"r");

        if (!fp && errno == ENOENT) {
            init = true;
        }
    }
    g_free (fname);

    if (init || all) {
        int j = 0;
        printf("init set\n");
        for (int i = 0; i < chunks.size(); i++) {
            if (!chunks.value(i).hide) {
                ui->tableWidget->setRowCount(ui->tableWidget->rowCount()+1);
                ui->tableWidget->setVerticalHeaderItem(j, new QTableWidgetItem(QString("%1").arg(chunks.value(i).name)));
                ui->tableWidget->setItem(j,0, new QTableWidgetItem(QString("%1").arg(selected_assoc->chunk_count[chunks.value(i).id])));
                ui->tableWidget->setItem(j,1, new QTableWidgetItem(QString("%1").arg(selected_assoc->ep1_chunk_count[chunks.value(i).id])));
                ui->tableWidget->setItem(j,2, new QTableWidgetItem(QString("%1").arg(selected_assoc->ep2_chunk_count[chunks.value(i).id])));
                j++;
            }
        }
        for (int i = 0; i < chunks.size(); i++) {
            if (chunks.value(i).hide) {
                ui->tableWidget->setRowCount(ui->tableWidget->rowCount()+1);
               /* ui->tableWidget->setVerticalHeaderItem(j, new QTableWidgetItem(QString("%1").arg(chunks.value(i).name)));
                ui->tableWidget->setItem(j,0, new QTableWidgetItem(QString("%1").arg(selected_assoc->chunk_count[chunks.value(i).id])));
                ui->tableWidget->setItem(j,1, new QTableWidgetItem(QString("%1").arg(selected_assoc->ep1_chunk_count[chunks.value(i).id])));
                ui->tableWidget->setItem(j,2, new QTableWidgetItem(QString("%1").arg(selected_assoc->ep2_chunk_count[chunks.value(i).id])));*/
                ui->tableWidget->hideRow(j);
                j++;
            }
        }
    } else {
        char* line = NULL;
        size_t cap = 0;
        ssize_t len;
        char *token, id[5];
        int i = 0, j = 0;
        struct chunkTypes temp;

        getline(&line, &cap, fp);
        while ((len = getline(&line, &cap, fp)) > 0 ) {
            token = strtok(line, ",");
            /* Get rid of the quotation marks */
            QString ch = QString(token).mid(1, (int)strlen(token)-2);
            strcpy(id, qPrintable(ch));
            temp.id = atoi(id);
            while(token != NULL) {
                token = strtok(NULL, ",");
                if (token) {
                    if ((strstr(token, "Hide"))) {
                        temp.hide = 1;
                    } else if ((strstr(token, "Show"))) {
                        temp.hide = 0;
                    } else {
                        QString ch = QString(token).mid(1, (int)strlen(token)-2);
                        strcpy(temp.name, qPrintable(ch));
                    }
                }
            }
            if (!temp.hide) {
                ui->tableWidget->setRowCount(ui->tableWidget->rowCount()+1);
                ui->tableWidget->setVerticalHeaderItem(j, new QTableWidgetItem(QString("%1").arg(temp.name)));
                ui->tableWidget->setItem(j,0, new QTableWidgetItem(QString("%1").arg(selected_assoc->chunk_count[temp.id])));
                ui->tableWidget->setItem(j,1, new QTableWidgetItem(QString("%1").arg(selected_assoc->ep1_chunk_count[temp.id])));
                ui->tableWidget->setItem(j,2, new QTableWidgetItem(QString("%1").arg(selected_assoc->ep2_chunk_count[temp.id])));
                j++;
            }
            chunks.insert(i, temp);
            i++;
        }
        j = ui->tableWidget->rowCount();
        for (int i = 0; i < chunks.size(); i++) {
            if (chunks.value(i).hide) {
                ui->tableWidget->setRowCount(ui->tableWidget->rowCount()+1);
               /* ui->tableWidget->setVerticalHeaderItem(j, new QTableWidgetItem(QString("%1").arg(chunks.value(i).name)));
                ui->tableWidget->setItem(j,0, new QTableWidgetItem(QString("%1").arg(selected_assoc->chunk_count[chunks.value(i).id])));
                ui->tableWidget->setItem(j,1, new QTableWidgetItem(QString("%1").arg(selected_assoc->ep1_chunk_count[chunks.value(i).id])));
                ui->tableWidget->setItem(j,2, new QTableWidgetItem(QString("%1").arg(selected_assoc->ep2_chunk_count[chunks.value(i).id])));*/
                ui->tableWidget->hideRow(j);
                j++;
            }
        }
        fclose(fp);
    }
}

void SCTPChunkStatisticsDialog::contextMenuEvent( QContextMenuEvent * event)
{
    selected_point = event->pos();
    QTableWidgetItem *item = ui->tableWidget->itemAt(selected_point.x(), selected_point.y()-60);
    if (item) {
        printf("clicked on row %d\n", item->row());
        printf("Inhalt von %d: %s\n", item->row(), ui->tableWidget->verticalHeaderItem(item->row())->text().toUtf8().constData());
        ctx_menu_.exec(event->globalPos());
    }
    else
        printf("nichts da\n");

}



void SCTPChunkStatisticsDialog::on_pushButton_clicked()
{
    FILE* fp;

    pref_t *pref = prefs_find_preference(prefs_find_module("sctp"),"statistics_chunk_types");

    uat_t *uat = pref->varp.uat;

    gchar* fname = uat_get_actual_filename(uat,TRUE);

    if (!fname ) {
        printf("no filename\n");
        return;
    }
    fp = ws_fopen(fname,"w");

    if (!fp && errno == ENOENT) {
        gchar *pf_dir_path = NULL;
        if (create_persconffile_dir(&pf_dir_path) != 0) {
            printf("on_pushButton_clicked: error creating '%s'", pf_dir_path);
            g_free (pf_dir_path);
            return;
        }
        fp = ws_fopen(fname,"w");
    }

    if (!fp) {
        printf("on_pushButton_clicked: error opening '%s': %s",fname,g_strerror(errno));
        return;
    }

    g_free (fname);

    fprintf(fp,"# This file is automatically generated, DO NOT MODIFY.\n");
    char str[40];

    for (int i = 0; i < chunks.size(); i++) {
        sprintf(str, "\"%d\",\"%s\",\"%s\"\n", chunks.value(i).id, chunks.value(i).name, (chunks.value(i).hide==0?"Show":"Hide"));
        fputs(str, fp);
        void *rec = g_malloc0(uat->record_size);
        uat_add_record(uat, rec, TRUE);
        if (uat->free_cb) {
            uat->free_cb(rec);
        }
        g_free(rec);
    }

    fclose(fp);
}

void SCTPChunkStatisticsDialog::on_sectionMoved(int logicalIndex, int oldVisualIndex, int newVisualIndex)
{
    printf("logicalIndex=%d, oldVisualIndex=%d, newVisualIndex=%d\n", logicalIndex, oldVisualIndex, newVisualIndex);
}

void SCTPChunkStatisticsDialog::on_actionHideChunkType_triggered()
{
    int row;

    QTableWidgetItem *item = ui->tableWidget->itemAt(selected_point.x(), selected_point.y()-60);
    if (item) {
        row = item->row();
        ui->tableWidget->hideRow(row);
        QTableWidgetItem *item = ui->tableWidget->verticalHeaderItem(row);
        QMap<int, struct chunkTypes>::iterator iter;
        for (iter = chunks.begin(); iter != chunks.end(); ++iter) {
            if (strcmp(iter.value().name, item->text().toUtf8().constData()) == 0) {
                iter.value().hide = true;
                break;
            }
        }
    }

}

void SCTPChunkStatisticsDialog::on_actionChunkTypePreferences_triggered()
{
    const gchar* err = NULL;

    pref_t *pref = prefs_find_preference(prefs_find_module("sctp"),"statistics_chunk_types");
    uat_t *uat = pref->varp.uat;
    uat_clear(uat);

    uat_load(pref->varp.uat, &err);
    if (err) {
        printf("Error loading table '%s': %s",pref->varp.uat->name,err);
    }

    UatDialog *uatdialog = new UatDialog(this, pref->varp.uat);
    uatdialog->exec();
    ui->tableWidget->clear();
    ui->tableWidget->setRowCount(0);
    ui->tableWidget->setHorizontalHeaderItem(0, new QTableWidgetItem(QString("Association")));
    ui->tableWidget->setHorizontalHeaderItem(1, new QTableWidgetItem(QString("Endpoint 1")));
    ui->tableWidget->setHorizontalHeaderItem(2, new QTableWidgetItem(QString("Endpoint 2")));
    fillTable();
}

void SCTPChunkStatisticsDialog::on_actionShowAllChunkTypes_triggered()
{
    ui->tableWidget->clear();
    ui->tableWidget->setRowCount(0);
    ui->tableWidget->setHorizontalHeaderItem(0, new QTableWidgetItem(QString("Association")));
    ui->tableWidget->setHorizontalHeaderItem(1, new QTableWidgetItem(QString("Endpoint 1")));
    ui->tableWidget->setHorizontalHeaderItem(2, new QTableWidgetItem(QString("Endpoint 2")));
    printf ("on_actionShowAllChunkTypes_triggered: assoc=%d\n", selected_assoc->assoc_id);
    initializeChunkMap();
    fillTable(true);
}
