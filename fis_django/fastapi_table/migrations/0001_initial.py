# Generated by Django 3.1.4 on 2020-12-22 16:34

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Files',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file_id', models.CharField(max_length=64)),
                ('file_name', models.TextField()),
                ('file_date_scanned', models.CharField(max_length=23)),
                ('score', models.CharField(max_length=7)),
                ('severity', models.CharField(max_length=6)),
                ('exec_parent_count', models.IntegerField()),
            ],
        ),
    ]
